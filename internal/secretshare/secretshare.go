// Package secretshare is the client side of VT-SecretShare for programs that
// are not a browser: the same encryption as web/crypto.js and the three API
// calls. A link made here opens in the web UI and the other way round.
//
// Wire format, shared with the browser:
//
//	ciphertext  = base64( iv[12] || AES-256-GCM(plaintext) with its tag )
//	key         = base64url without padding of the 32 raw key bytes; it is the
//	              #fragment of the link and is never sent to the server
//	verifier    = base64url( HKDF-SHA256(key, no salt, VerifierInfo, 32 bytes) )
//	             sent on reveal; the server stored base64url(SHA-256(verifier))
//	             on create and only burns the secret when they match
package secretshare

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// VerifierInfo is the HKDF info string; web/crypto.js uses the same one.
const VerifierInfo = "vt-secretshare/reveal-verifier/v1"

// MaxPlaintext is what fits under the server's default 256 KiB ciphertext
// limit once the IV, the tag and base64 are added.
const MaxPlaintext = 256*1024/4*3 - 12 - 16

const (
	keyLen = 32
	ivLen  = 12
)

var (
	// ErrGone: the secret was already opened, expired, or never existed.
	ErrGone = errors.New("the secret is gone: it was already opened, it expired, or the link is wrong")
	// ErrWrongKey: the server compared the key and refused; the secret is intact.
	ErrWrongKey = errors.New("the key in the link does not match; the secret was not opened and is still there")
	// ErrTooLarge: the server refused the size.
	ErrTooLarge = errors.New("the secret is too large (the limit is about 190 KB)")
	// ErrUndecryptable: the server handed over (and deleted) a ciphertext this
	// key cannot open. Only secrets stored without a verifier can end here.
	ErrUndecryptable = errors.New("the secret was deleted from the server but this key cannot decrypt it")
)

// RetryError is a refusal that left the secret untouched: the rate limit, or
// the store being down. After is the server's Retry-After.
type RetryError struct{ After time.Duration }

func (e *RetryError) Error() string {
	return fmt.Sprintf("the server is refusing requests for now; nothing was opened, try again in %s", e.After)
}

// ServerError is any other non-2xx answer.
type ServerError struct {
	Status  int
	Message string
}

func (e *ServerError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("server answered HTTP %d", e.Status)
	}
	return fmt.Sprintf("server answered HTTP %d: %s", e.Status, e.Message)
}

// ---- encryption ----

// Encrypt seals plaintext under a fresh random key.
func Encrypt(plaintext []byte) (ciphertext, key string, err error) {
	raw := make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", "", err
	}
	gcm, err := newGCM(raw)
	if err != nil {
		return "", "", err
	}
	iv := make([]byte, ivLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", "", err
	}
	blob := gcm.Seal(iv, iv, plaintext, nil) // iv || ciphertext || tag
	return base64.StdEncoding.EncodeToString(blob), base64.RawURLEncoding.EncodeToString(raw), nil
}

// Decrypt opens a ciphertext blob with the key from a link.
func Decrypt(ciphertext, key string) ([]byte, error) {
	raw, err := decodeKey(key)
	if err != nil {
		return nil, err
	}
	blob, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ciphertext is not base64: %w", err)
	}
	if len(blob) < ivLen+16 {
		return nil, errors.New("ciphertext is too short")
	}
	gcm, err := newGCM(raw)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, blob[:ivLen], blob[ivLen:], nil)
}

func newGCM(raw []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

var keyShape = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// ValidKey reports whether key looks like the #fragment of a link.
func ValidKey(key string) bool {
	_, err := decodeKey(key)
	return err == nil
}

func decodeKey(key string) ([]byte, error) {
	if !keyShape.MatchString(key) {
		return nil, errors.New("the key (the part of the link after #) is missing or cut short")
	}
	raw, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil || len(raw) != keyLen {
		return nil, errors.New("the key (the part of the link after #) is not valid")
	}
	return raw, nil
}

// Verifier derives the value that proves, on reveal, that the caller holds
// the key. The key cannot be recovered from it.
func Verifier(key string) (string, error) {
	v, err := verifierBytes(key)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(v), nil
}

// VerifierHash is what the server stores on create: SHA-256 of the verifier.
func VerifierHash(key string) (string, error) {
	v, err := verifierBytes(key)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(v)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func verifierBytes(key string) ([]byte, error) {
	raw, err := decodeKey(key)
	if err != nil {
		return nil, err
	}
	return hkdf.Key(sha256.New, raw, nil, VerifierInfo, 32)
}

// ---- links ----

// Link is a share link taken apart: https://host/s/<ID>#<Key>.
type Link struct {
	Server string // scheme://host, plus any path the instance lives under
	ID     string
	Key    string // empty when the link was given without its #fragment
}

func (l Link) String() string {
	s := l.Server + "/s/" + l.ID
	if l.Key != "" {
		s += "#" + l.Key
	}
	return s
}

var idShape = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// ParseLink accepts a share link, with or without the query string that links
// made before v1.1 carried. The key is checked only if needKey is set, since
// asking for the status of a link does not need it.
func ParseLink(raw string, needKey bool) (Link, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return Link{}, fmt.Errorf("%q is not a share link (expected https://…/s/<id>#<key>)", raw)
	}
	i := strings.LastIndex(u.Path, "/s/")
	if i < 0 {
		return Link{}, fmt.Errorf("%q is not a share link (expected https://…/s/<id>#<key>)", raw)
	}
	id := u.Path[i+len("/s/"):]
	if !idShape.MatchString(id) {
		return Link{}, fmt.Errorf("%q is not a share link (expected https://…/s/<id>#<key>)", raw)
	}
	l := Link{Server: u.Scheme + "://" + u.Host + u.Path[:i], ID: id, Key: u.Fragment}
	if needKey {
		if _, err := decodeKey(l.Key); err != nil {
			return Link{}, err
		}
	}
	return l, nil
}

// ---- API ----

// Client talks to an instance. The zero value works.
type Client struct {
	HTTP      *http.Client
	UserAgent string
}

func (c *Client) do(ctx context.Context, method, endpoint string, body any, header map[string]string) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	return hc.Do(req)
}

// apiError turns a non-2xx response into one of the package's errors.
func apiError(res *http.Response) error {
	var body struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	_ = json.Unmarshal(raw, &body)
	switch {
	case res.StatusCode == http.StatusNotFound:
		return ErrGone
	case res.StatusCode == http.StatusForbidden && body.Code == "wrong_key":
		return ErrWrongKey
	case res.StatusCode == http.StatusRequestEntityTooLarge:
		return ErrTooLarge
	case res.StatusCode == http.StatusTooManyRequests || res.StatusCode == http.StatusServiceUnavailable:
		after := 60
		if n, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && n > 0 {
			after = n
		}
		return &RetryError{After: time.Duration(after) * time.Second}
	}
	return &ServerError{Status: res.StatusCode, Message: body.Error}
}

// Created is a secret that was just stored.
type Created struct {
	Link      Link
	TTL       time.Duration // what the server granted, after its own limits
	ExpiresAt time.Time
}

// Create encrypts plaintext locally and stores the ciphertext on server. A
// zero ttl asks for the server's default.
func (c *Client) Create(ctx context.Context, server string, plaintext []byte, ttl time.Duration) (Created, error) {
	server = strings.TrimRight(server, "/")
	if len(plaintext) > MaxPlaintext {
		return Created{}, ErrTooLarge
	}
	ciphertext, key, err := Encrypt(plaintext)
	if err != nil {
		return Created{}, err
	}
	hash, err := VerifierHash(key)
	if err != nil {
		return Created{}, err
	}
	res, err := c.do(ctx, http.MethodPost, server+"/api/secret", map[string]any{
		"ciphertext":    ciphertext,
		"ttl_seconds":   int(ttl / time.Second),
		"verifier_hash": hash,
	}, nil)
	if err != nil {
		return Created{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return Created{}, apiError(res)
	}
	var out struct {
		ID         string `json:"id"`
		ShareURL   string `json:"share_url"`
		TTLSeconds int    `json:"ttl_seconds"`
		ExpiresAt  string `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<16)).Decode(&out); err != nil || out.ID == "" {
		return Created{}, errors.New("the server's answer was not understood")
	}
	// share_url carries the instance's public address (BASE_URL), which can
	// differ from the one this request went to.
	link, err := ParseLink(out.ShareURL, false)
	if err != nil || link.ID != out.ID {
		link = Link{Server: server, ID: out.ID}
	}
	link.Key = key
	expires, _ := time.Parse(time.RFC3339, out.ExpiresAt)
	return Created{Link: link, TTL: time.Duration(out.TTLSeconds) * time.Second, ExpiresAt: expires}, nil
}

// Reveal opens the link: the server deletes the secret as it hands it over,
// and the plaintext is decrypted here.
func (c *Client) Reveal(ctx context.Context, link Link) ([]byte, error) {
	verifier, err := Verifier(link.Key)
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, http.MethodPost, link.Server+"/api/secret/"+url.PathEscape(link.ID)+"/reveal",
		map[string]string{"verifier": verifier}, map[string]string{"X-VT-Reveal": "1"})
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, apiError(res)
	}
	var out struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&out); err != nil {
		return nil, errors.New("the server's answer was not understood")
	}
	plaintext, err := Decrypt(out.Ciphertext, link.Key)
	if err != nil {
		return nil, ErrUndecryptable
	}
	return plaintext, nil
}

// Status is whether a secret is still waiting to be opened.
type Status struct {
	TTL       time.Duration
	ExpiresAt time.Time
}

// Check asks whether the secret still exists, without opening it. A secret
// that is gone comes back as ErrGone.
func (c *Client) Check(ctx context.Context, link Link) (Status, error) {
	res, err := c.do(ctx, http.MethodGet, link.Server+"/api/secret/"+url.PathEscape(link.ID)+"/meta", nil, nil)
	if err != nil {
		return Status{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return Status{}, apiError(res)
	}
	var out struct {
		TTLSeconds int    `json:"ttl_seconds"`
		ExpiresAt  string `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<16)).Decode(&out); err != nil {
		return Status{}, errors.New("the server's answer was not understood")
	}
	expires, _ := time.Parse(time.RFC3339, out.ExpiresAt)
	return Status{TTL: time.Duration(out.TTLSeconds) * time.Second, ExpiresAt: expires}, nil
}
