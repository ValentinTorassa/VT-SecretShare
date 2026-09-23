package main

import (
	"context"
	"errors"
	"fmt"
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

// rateLimitPrefix namespaces the per-client request counters (see ratelimit.go).
// They can never collide with secrets, which live under keyPrefix.
const rateLimitPrefix = "ratelimit:"

// Store is the only thing that talks to Redis. The entire persistence model for
// secrets is two commands: SET ... NX EX (write once, auto-expire) and GETDEL
// (read once, atomically delete). That atomic read-and-delete is what
// guarantees a secret can be consumed exactly one time even under concurrent
// reads. The only other keys are short-lived rate-limit counters (Hit).
type Store struct {
	rdb *redis.Client
}

func NewStore(addr, password string) *Store {
	return newStoreWithOptions(&redis.Options{
		Addr:     addr,
		Password: password,
	})
}

// newStoreWithOptions makes every Redis call honour its context deadline, so the
// short timeouts used by /healthz and the rate limiters hold even when Redis
// hangs instead of refusing connections. Calls without a deadline keep
// go-redis's default read/write timeouts.
func newStoreWithOptions(opt *redis.Options) *Store {
	opt.ContextTimeoutEnabled = true
	return &Store{rdb: redis.NewClient(opt)}
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

// hitScript is a fixed-window counter: INCR, and on the first hit PEXPIRE to the
// window length. It runs as one script so the two steps are atomic; a crash or
// timeout between them can never leave a counter without a TTL (which would
// lock the client out for ever). A counter that somehow has no TTL is given one.
// Returns {count, remaining window in ms}.
var hitScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {n, ttl}
`)

// Hit counts one request against a rate-limit counter and returns the number of
// requests seen in the current window and the time until the window resets.
// key is an opaque hash built by the caller, never a raw client address.
func (s *Store) Hit(ctx context.Context, key string, window time.Duration) (int64, time.Duration, error) {
	res, err := hitScript.Run(ctx, s.rdb, []string{rateLimitPrefix + key}, window.Milliseconds()).Int64Slice()
	if err != nil {
		return 0, 0, err
	}
	if len(res) != 2 {
		return 0, 0, fmt.Errorf("rate limit script: unexpected reply length %d", len(res))
	}
	return res[0], time.Duration(res[1]) * time.Millisecond, nil
}
