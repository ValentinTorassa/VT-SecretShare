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

// ErrWrongKey means the secret exists but the reveal did not prove knowledge of
// its key (see verifier below). The secret is left untouched.
var ErrWrongKey = errors.New("key does not match this secret")

// verifierPrefix marks a stored value that carries a key verifier:
//
//	v1:<verifier hash>:<ciphertext>
//
// The browser derives a verifier from the AES key with HKDF (a different
// output than the key itself, so it reveals nothing about it) and sends only
// the SHA-256 of that verifier on create. A reveal must present the verifier,
// and the Lua script below compares it before deleting, so a mistyped or
// truncated link no longer destroys the secret. Base64 has no ':', so a
// value written before verifiers existed (plain base64 ciphertext) can never
// be mistaken for one; those keep the original burn-on-first-reveal behaviour.
const verifierPrefix = "v1:"

const keyPrefix = "secret:"

// rateLimitPrefix namespaces the per-client request counters (see ratelimit.go).
// They can never collide with secrets, which live under keyPrefix.
const rateLimitPrefix = "ratelimit:"

// Store is the only thing that talks to Redis. The entire persistence model for
// secrets is SET ... NX EX (write once, auto-expire) and one Lua script that
// checks the key verifier and deletes in the same atomic step (read once).
// That atomic check-and-delete is what guarantees a secret can be consumed
// exactly one time even under concurrent reads. The only other keys are
// short-lived rate-limit counters (Hit).
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
// key, so this blob is useless to anyone who dumps Redis. verifierHash is the
// base64url SHA-256 of the key verifier; empty stores a legacy value that any
// reveal burns.
func (s *Store) Save(ctx context.Context, id, ciphertext, verifierHash string, ttl time.Duration) error {
	value := ciphertext
	if verifierHash != "" {
		value = verifierPrefix + verifierHash + ":" + ciphertext
	}
	ok, err := s.rdb.SetNX(ctx, keyPrefix+id, value, ttl).Result()
	if err != nil {
		return err
	}
	if !ok {
		return ErrExists
	}
	return nil
}

// burnScript reads the secret, checks the verifier when the value carries one,
// and deletes it, all in one atomic step: two people racing on the same link
// can never both win, and a wrong verifier never deletes anything.
// Returns {status, ciphertext}: 0 missing, 1 burned, 2 wrong key, 3 corrupt.
var burnScript = redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if not v then return {0, ''} end
if string.sub(v, 1, 3) == 'v1:' then
  local sep = string.find(v, ':', 4, true)
  if not sep then return {3, ''} end
  if string.sub(v, 4, sep - 1) ~= ARGV[1] then return {2, ''} end
  redis.call('DEL', KEYS[1])
  return {1, string.sub(v, sep + 1)}
end
redis.call('DEL', KEYS[1])
return {1, v}
`)

// Burn atomically reads and deletes the secret. verifierHash is the base64url
// SHA-256 of the verifier the reveal presented ("" if it sent none). A value
// that carries a verifier is only deleted when the hashes match; otherwise
// ErrWrongKey and the secret stays. Legacy values are burned as before.
func (s *Store) Burn(ctx context.Context, id, verifierHash string) (string, error) {
	res, err := burnScript.Run(ctx, s.rdb, []string{keyPrefix + id}, verifierHash).Slice()
	if err != nil {
		return "", err
	}
	if len(res) != 2 {
		return "", fmt.Errorf("burn script: unexpected reply length %d", len(res))
	}
	status, _ := res[0].(int64)
	ciphertext, _ := res[1].(string)
	switch status {
	case 0:
		return "", ErrNotFound
	case 1:
		return ciphertext, nil
	case 2:
		return "", ErrWrongKey
	default:
		return "", fmt.Errorf("burn script: stored value for %q is malformed", id)
	}
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
