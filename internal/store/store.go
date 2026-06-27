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

// PutSession records a session token with its absolute expiry.
func (s *Store) PutSession(token string, expiry time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSessions).Put([]byte(token), []byte(expiry.Format(time.RFC3339)))
	})
}

// SessionValid reports whether token names a session that has not expired.
func (s *Store) SessionValid(token string) (bool, error) {
	if token == "" {
		return false, nil
	}
	var ok bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketSessions).Get([]byte(token))
		if v == nil {
			return nil
		}
		exp, err := time.Parse(time.RFC3339, string(v))
		if err != nil {
			return nil
		}
		ok = time.Now().Before(exp)
		return nil
	})
	return ok, err
}
