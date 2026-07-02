// The WebAuthn ceremonies and recovery-code flow. Registration is
// trust-on-first-use and only reachable while the device is unprovisioned
// or from an authenticated session (adding a second passkey).
package httpapi

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/framefilter/mistui/internal/auth"
)

const (
	challengeTTL = 2 * time.Minute
	// A step-up credit must be spent quickly: the UI performs the
	// destructive call in the same interaction as the touch.
	stepUpTTL = 2 * time.Minute
	// Sessions expire after sessionIdle of inactivity (slid forward on each
	// authenticated request) and, regardless of activity, sessionAbsolute
	// after login. Re-auth is a single WebAuthn touch, so these are short
	// on purpose — the passkey is what makes frequent re-auth cheap.
	sessionIdle     = 15 * time.Minute
	sessionAbsolute = 12 * time.Hour
	sessionBumpMin  = 30 * time.Second // throttle the slide's writes
	recoveryHashKey = "recovery_hash"
)

// ttlSet is a mutex-guarded set of single-use, expiring keys. It backs both
// ceremony challenges and step-up credits. In-memory on purpose: an entry
// that doesn't survive a daemon restart is a feature.
type ttlSet struct {
	mu  sync.Mutex
	m   map[string]time.Time
	ttl time.Duration
}

func newTTLSet(ttl time.Duration) *ttlSet {
	return &ttlSet{m: make(map[string]time.Time), ttl: ttl}
}

// grant adds (or refreshes) key with the set's TTL.
func (c *ttlSet) grant(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, exp := range c.m { // opportunistic GC; the map stays tiny
		if now.After(exp) {
			delete(c.m, k)
		}
	}
	c.m[key] = now.Add(c.ttl)
}

// issue mints a fresh random key and grants it — ceremony challenges.
func (c *ttlSet) issue() (string, error) {
	key, err := auth.NewToken()
	if err != nil {
		return "", err
	}
	c.grant(key)
	return key, nil
}

// consume removes key and reports whether it was present and unexpired —
// each entry answers exactly once.
func (c *ttlSet) consume(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.m[key]
	delete(c.m, key)
	return ok && time.Now().Before(exp)
}

func (s *Server) provisioned() bool {
	n, _ := s.store.CredentialCount()
	return n > 0
}

func (s *Server) issueSession(w http.ResponseWriter) error {
	tok, err := auth.NewToken()
	if err != nil {
		return err
	}
	now := time.Now()
	if err := s.store.PutSession(tok, now, now); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  now.Add(sessionAbsolute), // the hard cap; idle is enforced server-side
	})
	return nil
}

// sessionValid reports whether the request carries a live session. When
// slide is true it advances the idle timeout (throttled) — real actions
// slide, passive checks like /api/session do not, so polling can't keep a
// session alive forever. Expired tokens are deleted as they're seen.
func (s *Server) sessionValid(r *http.Request, slide bool) bool {
	tok := sessionToken(r)
	issued, seen, ok, err := s.store.Session(tok)
	if err != nil || !ok {
		return false
	}
	now := time.Now()
	if now.After(seen.Add(sessionIdle)) || now.After(issued.Add(sessionAbsolute)) {
		_ = s.store.DeleteSession(tok)
		return false
	}
	if slide && now.Sub(seen) > sessionBumpMin {
		_ = s.store.BumpSession(tok, now)
	}
	return true
}

// logout revokes the current session server-side and clears the cookie. It
// is intentionally not session-gated: an already-expired session should
// still be able to clear its stale cookie.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if tok := sessionToken(r); tok != "" {
		_ = s.store.DeleteSession(tok)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- registration (TOFU) ---

func (s *Server) registerBegin(w http.ResponseWriter, r *http.Request) {
	if s.provisioned() {
		if !s.sessionValid(r, false) {
			http.Error(w, "already provisioned", http.StatusForbidden)
			return
		}
	}
	ch, err := s.chals.issue()
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	uid, err := auth.NewToken()
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rpId":      s.rpID,
		"challenge": ch,
		"user":      map[string]string{"id": uid, "name": "MistUI Owner"},
	})
}

type registerReq struct {
	ClientDataJSON    []byte `json:"clientDataJSON"`
	AttestationObject []byte `json:"attestationObject"`
}

func (s *Server) registerFinish(w http.ResponseWriter, r *http.Request) {
	first := !s.provisioned()
	if !first {
		if !s.sessionValid(r, false) {
			http.Error(w, "already provisioned", http.StatusForbidden)
			return
		}
	}
	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.verifyCeremony(w, req.ClientDataJSON, auth.CeremonyCreate) {
		return
	}
	credID, cose, err := auth.ParseRegistration(req.AttestationObject, s.rpID)
	if err != nil {
		http.Error(w, "registration rejected", http.StatusBadRequest)
		return
	}
	id := base64.RawURLEncoding.EncodeToString(credID)
	if err := s.store.PutCredential(id, cose); err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{"registered": true, "credentialId": id}
	if first {
		// Provisioning: mint the single-use recovery code. The plaintext
		// appears exactly once, in this response; only its hash is stored.
		code, err := auth.NewToken()
		if err != nil {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		if err := s.store.PutConfig(recoveryHashKey, auth.HashToken(code)); err != nil {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		resp["recoveryCode"] = code
	}
	if err := s.issueSession(w); err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- login ---

func (s *Server) loginBegin(w http.ResponseWriter, r *http.Request) {
	if !s.provisioned() {
		http.Error(w, "unprovisioned", http.StatusConflict)
		return
	}
	ids, err := s.store.ListCredentialIDs()
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	ch, err := s.chals.issue()
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rpId": s.rpID, "challenge": ch, "credentialIds": ids,
	})
}

type loginReq struct {
	CredentialID      string `json:"credentialId"`
	AuthenticatorData []byte `json:"authenticatorData"`
	ClientDataJSON    []byte `json:"clientDataJSON"`
	Signature         []byte `json:"signature"`
}

func (s *Server) loginFinish(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.verifyCeremony(w, req.ClientDataJSON, auth.CeremonyGet) {
		return
	}
	if err := auth.VerifyAuthData(req.AuthenticatorData, s.rpID); err != nil {
		http.Error(w, "denied", http.StatusUnauthorized)
		return
	}
	cose, err := s.store.Credential(req.CredentialID)
	if err != nil || cose == nil {
		http.Error(w, "denied", http.StatusUnauthorized)
		return
	}
	pub, err := auth.ParseCOSE(cose)
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if !auth.VerifyAssertion(pub, req.AuthenticatorData, req.ClientDataJSON, req.Signature) {
		http.Error(w, "denied", http.StatusUnauthorized)
		return
	}
	if err := s.issueSession(w); err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true})
}

// verifyCeremony extracts + consumes the challenge and runs the shared
// clientDataJSON checks, writing the error response on failure.
func (s *Server) verifyCeremony(w http.ResponseWriter, clientDataJSON []byte, ceremony string) bool {
	var cd struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(clientDataJSON, &cd); err != nil || !s.chals.consume(cd.Challenge) {
		http.Error(w, "stale or unknown challenge", http.StatusBadRequest)
		return false
	}
	if err := auth.VerifyClientData(clientDataJSON, ceremony, cd.Challenge, s.origins); err != nil {
		http.Error(w, "denied", http.StatusUnauthorized)
		return false
	}
	return true
}

// --- recovery ---

func (s *Server) loginRecovery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	stored, err := s.store.Config(recoveryHashKey)
	if err != nil || stored == nil {
		http.Error(w, "denied", http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare(stored, auth.HashToken(req.Code)) != 1 {
		http.Error(w, "denied", http.StatusUnauthorized)
		return
	}
	// Single-use: burn it before the session exists.
	if err := s.store.DeleteConfig(recoveryHashKey); err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if err := s.issueSession(w); err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "recoveryUsed": true})
}

// --- step-up re-auth (§4.2) ---
//
// Destructive actions require a FRESH WebAuthn assertion, not merely a live
// session. A successful step-up ceremony grants the session exactly one
// credit (stepUpTTL to spend it); each gated endpoint consumes it. The
// endpoints answer 428 when the credit is missing, and the UI treats that
// as "run the ceremony, then retry" — so an expired credit or a daemon
// restart degrades to one extra touch, never a dead end. Sessions from the
// recovery code hold no passkey and so cannot step up until a new one is
// registered — which is exactly what the recovery flow demands anyway.

func (s *Server) stepUpBegin(w http.ResponseWriter, r *http.Request) {
	ids, err := s.store.ListCredentialIDs()
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	ch, err := s.chals.issue()
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rpId": s.rpID, "challenge": ch, "credentialIds": ids,
	})
}

func (s *Server) stepUpFinish(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.verifyCeremony(w, req.ClientDataJSON, auth.CeremonyGet) {
		return
	}
	if err := auth.VerifyAuthData(req.AuthenticatorData, s.rpID); err != nil {
		http.Error(w, "denied", http.StatusUnauthorized)
		return
	}
	cose, err := s.store.Credential(req.CredentialID)
	if err != nil || cose == nil {
		http.Error(w, "denied", http.StatusUnauthorized)
		return
	}
	pub, err := auth.ParseCOSE(cose)
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if !auth.VerifyAssertion(pub, req.AuthenticatorData, req.ClientDataJSON, req.Signature) {
		http.Error(w, "denied", http.StatusUnauthorized)
		return
	}
	s.stepUps.grant(sessionToken(r))
	writeJSON(w, http.StatusOK, map[string]any{"steppedUp": true})
}

// requireStepUp gates a destructive handler behind one step-up credit.
// Callers wrap it inside requireSession.
func (s *Server) requireStepUp(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.stepUps.consume(sessionToken(r)) {
			// 428: the UI runs the step-up ceremony and retries.
			writeJSON(w, http.StatusPreconditionRequired,
				map[string]any{"stepUpRequired": true})
			return
		}
		next(w, r)
	}
}

func (s *Server) recoveryRegenerate(w http.ResponseWriter, r *http.Request) {
	code, err := auth.NewToken()
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if err := s.store.PutConfig(recoveryHashKey, auth.HashToken(code)); err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCode": code})
}
