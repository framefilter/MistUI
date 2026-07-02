// Package store is MistUI's embedded key/value store, backed by bbolt — a
// pure-Go, CGO-free B+tree that cross-compiles to mipsle (unlike SQLite).
// It holds WebAuthn credentials, active sessions, and small config values.
package store

import (
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketCreds    = []byte("credentials")
	bucketSessions = []byte("sessions")
	bucketConfig   = []byte("config")
)

// Store wraps a bbolt database with MistUI's buckets.
type Store struct{ db *bolt.DB }

// Open opens (or creates) the database at path and ensures every bucket
// exists.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketCreds, bucketSessions, bucketConfig} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the database file lock.
func (s *Store) Close() error { return s.db.Close() }

// PutCredential stores a WebAuthn credential's COSE public key under its ID.
func (s *Store) PutCredential(id string, cose []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCreds).Put([]byte(id), cose)
	})
}

// Credential returns the stored COSE public key for id, or nil if absent.
func (s *Store) Credential(id string) ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketCreds).Get([]byte(id)); v != nil {
			out = append([]byte{}, v...)
		}
		return nil
	})
	return out, err
}

// CredentialCount reports how many credentials are registered — zero means
// the device is unprovisioned and should run the first-boot wizard.
func (s *Store) CredentialCount() (int, error) {
	var n int
	err := s.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(bucketCreds).Stats().KeyN
		return nil
	})
	return n, err
}

// ListCredentialIDs returns the IDs of every registered credential, for a
// login ceremony's allowCredentials list.
func (s *Store) ListCredentialIDs() ([]string, error) {
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCreds).ForEach(func(k, _ []byte) error {
			out = append(out, string(k))
			return nil
		})
	})
	return out, err
}

// PutConfig stores a small config value, e.g. the recovery-code hash.
func (s *Store) PutConfig(key string, val []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketConfig).Put([]byte(key), val)
	})
}

// Config returns the stored value for key, or nil if absent.
func (s *Store) Config(key string) ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketConfig).Get([]byte(key)); v != nil {
			out = append([]byte{}, v...)
		}
		return nil
	})
	return out, err
}

// DeleteConfig removes key — how single-use values (the recovery hash) are
// consumed.
func (s *Store) DeleteConfig(key string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketConfig).Delete([]byte(key))
	})
}

// A session record stores two timestamps, "<issued>|<lastSeen>", so the
// policy layer can enforce both an idle timeout (from lastSeen) and an
// absolute cap (from issued). See internal/httpapi for the durations.

// PutSession creates (or replaces) a session with its issue and last-seen
// times.
func (s *Store) PutSession(token string, issued, seen time.Time) error {
	val := issued.Format(time.RFC3339) + "|" + seen.Format(time.RFC3339)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSessions).Put([]byte(token), []byte(val))
	})
}

// Session returns a token's issue and last-seen times. ok is false if the
// token is absent or the record is unparseable (treated as invalid).
func (s *Store) Session(token string) (issued, seen time.Time, ok bool, err error) {
	if token == "" {
		return time.Time{}, time.Time{}, false, nil
	}
	err = s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketSessions).Get([]byte(token))
		if v == nil {
			return nil
		}
		i, s, found := bytesCut(v, '|')
		if !found {
			return nil
		}
		it, e1 := time.Parse(time.RFC3339, string(i))
		st, e2 := time.Parse(time.RFC3339, string(s))
		if e1 != nil || e2 != nil {
			return nil
		}
		issued, seen, ok = it, st, true
		return nil
	})
	return issued, seen, ok, err
}

// BumpSession advances a session's last-seen time (the idle-timeout slide).
func (s *Store) BumpSession(token string, seen time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSessions)
		v := b.Get([]byte(token))
		if v == nil {
			return nil
		}
		issued, _, found := bytesCut(v, '|')
		if !found {
			return nil
		}
		// v (and issued) is bbolt-owned; build a fresh value to store.
		val := string(issued) + "|" + seen.Format(time.RFC3339)
		return b.Put([]byte(token), []byte(val))
	})
}

// DeleteSession removes a token — logout and expiry cleanup.
func (s *Store) DeleteSession(token string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSessions).Delete([]byte(token))
	})
}

func bytesCut(b []byte, sep byte) (before, after []byte, found bool) {
	for i, c := range b {
		if c == sep {
			return b[:i], b[i+1:], true
		}
	}
	return b, nil, false
}
