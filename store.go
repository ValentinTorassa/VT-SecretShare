package main

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrNotFound means the secret never existed, already expired (TTL), or was
// already burned (read once). We deliberately don't distinguish between these
// cases: telling a caller "this existed but was already read" leaks metadata.
var ErrNotFound = errors.New("secret not found, expired, or already burned")

// ErrExists means an id collision happened on Save (astronomically unlikely
// with 128 bits of entropy, but we never silently overwrite a live secret).
var ErrExists = errors.New("secret id already exists")

const keyPrefix = "secret:"

// Store is the only thing that talks to Redis. The entire persistence model is
// two commands: SET ... NX EX (write once, auto-expire) and GETDEL (read once,
// atomically delete). That atomic read-and-delete is what guarantees a secret
// can be consumed exactly one time even under concurrent reads.
type Store struct {
	rdb *redis.Client
}

func NewStore(addr, password string) *Store {
	return &Store{
		rdb: redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: password,
		}),
	}
}

func (s *Store) Ping(ctx context.Context) error {
	return s.rdb.Ping(ctx).Err()
}

func (s *Store) Close() error {
	return s.rdb.Close()
}

// Save stores an opaque ciphertext blob under id with a hard TTL. NX guarantees
// we never clobber an existing id. The server never sees the plaintext or the
// key, so this blob is useless to anyone who dumps Redis.
func (s *Store) Save(ctx context.Context, id, ciphertext string, ttl time.Duration) error {
	ok, err := s.rdb.SetNX(ctx, keyPrefix+id, ciphertext, ttl).Result()
	if err != nil {
		return err
	}
	if !ok {
		return ErrExists
	}
	return nil
}

// Burn atomically reads and deletes the secret. GETDEL (Redis 6.2+) does both
// in one round trip, so two people racing on the same link can never both win.
func (s *Store) Burn(ctx context.Context, id string) (string, error) {
	val, err := s.rdb.GetDel(ctx, keyPrefix+id).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return val, nil
}

// TTL reports remaining lifetime without consuming the secret (used by the
// metadata endpoint so the UI can show "expires in ..." without burning it).
func (s *Store) TTL(ctx context.Context, id string) (time.Duration, error) {
	d, err := s.rdb.TTL(ctx, keyPrefix+id).Result()
	if err != nil {
		return 0, err
	}
	// redis returns -2 if the key is missing, -1 if it has no expiry.
	if d < 0 {
		return 0, ErrNotFound
	}
	return d, nil
}
