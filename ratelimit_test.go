package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Uses the isolated redis-server from store_test.go; "Redis down" is a store
// pointed at a socket that does not exist.

func deadStore(t *testing.T) *Store {
	t.Helper()
	s := newStoreWithOptions(&redis.Options{
		Network:     "unix",
		Addr:        filepath.Join(t.TempDir(), "no-redis-here.sock"),
		MaxRetries:  -1,
		DialTimeout: 200 * time.Millisecond,
	})
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testConfig() config {
	proxies, err := parseTrustedProxies(defaultTrustedProxies)
	if err != nil {
		panic(err)
	}
	return config{
		baseURL:        "http://example.test",
		maxCipherLen:   1024,
		defaultTTL:     time.Hour,
		maxTTL:         24 * time.Hour,
		createLimit:    100,
		createWindow:   time.Minute,
		readLimit:      100,
		readWindow:     time.Minute,
		rateLimitSalt:  "test-salt-not-a-secret",
		trustedProxies: proxies,
	}
}

type request struct {
	method, path, remote, cfIP string
	body                       string
	reveal                     bool
}

func do(t *testing.T, h http.Handler, rq request) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(rq.method, rq.path, strings.NewReader(rq.body))
	req.RemoteAddr = rq.remote
	if rq.cfIP != "" {
		req.Header.Set("CF-Connecting-IP", rq.cfIP)
	}
	if rq.reveal {
		req.Header.Set("X-VT-Reveal", "1")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func createReq(remote, cfIP string) request {
	body := `{"ciphertext":"` + base64.StdEncoding.EncodeToString([]byte("opaque")) + `"}`
	return request{method: http.MethodPost, path: "/api/secret", remote: remote, cfIP: cfIP, body: body}
}

func errorBody(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return body["error"]
}

// ---- limiter math ----

func TestRetryAfterSecondsRoundsUp(t *testing.T) {
	for d, want := range map[time.Duration]int{
		0:                       1,
		-time.Second:            1,
		time.Millisecond:        1,
		time.Second:             1,
		time.Second + 1:         2,
		9*time.Second + 1:       10,
		10 * time.Minute:        600,
		10*time.Minute - 999999: 600,
	} {
		if got := retryAfterSeconds(d); got != want {
			t.Errorf("retryAfterSeconds(%v)=%d want %d", d, got, want)
		}
	}
}

func TestHitCountsFixedWindowAndExpires(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	window := 400 * time.Millisecond
	var firstTTL time.Duration
	for i := int64(1); i <= 5; i++ {
		n, ttl, err := s.Hit(ctx, "k", window)
		if err != nil {
			t.Fatal(err)
		}
		if n != i {
			t.Fatalf("hit %d counted as %d", i, n)
		}
		if ttl <= 0 || ttl > window {
			t.Fatalf("ttl %v outside (0, %v]", ttl, window)
		}
		if i == 1 {
			firstTTL = ttl
		} else if ttl > firstTTL {
			t.Fatalf("later hits must not extend a fixed window: %v > %v", ttl, firstTTL)
		}
	}
	time.Sleep(window + 100*time.Millisecond)
	if n, _, err := s.Hit(ctx, "k", window); err != nil || n != 1 {
		t.Fatalf("after the window: n=%d err=%v", n, err)
	}
}

func TestLimiterAllowsExactlyLimitThenReportsRemainingWindow(t *testing.T) {
	l := &rateLimiter{name: "read", limit: 3, window: time.Minute, store: testStore(t), salt: []byte("s")}
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		ok, _, err := l.allow(ctx, "198.51.100.1")
		if err != nil || !ok {
			t.Fatalf("request %d: ok=%v err=%v", i, ok, err)
		}
	}
	ok, retry, err := l.allow(ctx, "198.51.100.1")
	if err != nil || ok {
		t.Fatalf("4th request: ok=%v err=%v", ok, err)
	}
	if retry <= 0 || retry > time.Minute {
		t.Fatalf("retry after %v", retry)
	}
	if ok, _, _ := l.allow(ctx, "198.51.100.2"); !ok {
		t.Fatal("another client must have its own budget")
	}
}

func TestLimiterIsAtomicUnderConcurrency(t *testing.T) {
	l := &rateLimiter{name: "create", limit: 10, window: time.Minute, store: testStore(t), salt: []byte("s")}
	var allowed atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, _, err := l.allow(context.Background(), "203.0.113.5")
			if err != nil {
				t.Error(err)
			}
			if ok {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if allowed.Load() != 10 {
		t.Fatalf("allowed=%d want 10", allowed.Load())
	}
}

func TestCounterKeysAreSaltedHashesWithTTL(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	a := &rateLimiter{name: "read", limit: 5, window: time.Minute, store: store, salt: []byte("salt-a")}
	b := &rateLimiter{name: "read", limit: 5, window: time.Minute, store: store, salt: []byte("salt-b")}
	if a.key("192.0.2.44") == b.key("192.0.2.44") {
		t.Fatal("the salt must change the key")
	}
	if _, _, err := a.allow(ctx, "192.0.2.44"); err != nil {
		t.Fatal(err)
	}
	keys, err := store.rdb.Keys(ctx, "*").Result()
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
	if strings.Contains(keys[0], "192.0.2") || !strings.HasPrefix(keys[0], "ratelimit:read:") || len(keys[0]) != len("ratelimit:read:")+32 {
		t.Fatalf("unexpected key %q", keys[0])
	}
	if ttl := store.rdb.PTTL(ctx, keys[0]).Val(); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("counter ttl %v", ttl)
	}
}

// ---- HTTP: 429 + Retry-After ----

func TestCreateOverLimitGets429WithRetryAfter(t *testing.T) {
	cfg := testConfig()
	cfg.createLimit, cfg.createWindow = 2, 90*time.Second
	h := newServer(cfg, testStore(t)).routes()
	for i := 0; i < 2; i++ {
		if rec := do(t, h, createReq("203.0.113.7:4000", "")); rec.Code != http.StatusCreated {
			t.Fatalf("create %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	rec := do(t, h, createReq("203.0.113.7:4001", ""))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d", rec.Code)
	}
	secs, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil || secs < 1 || secs > 90 {
		t.Fatalf("Retry-After %q", rec.Header().Get("Retry-After"))
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "too many requests") || !strings.Contains(msg, strconv.Itoa(secs)) {
		t.Fatalf("message %q", msg)
	}
	if rec := do(t, h, createReq("203.0.113.8:4000", "")); rec.Code != http.StatusCreated {
		t.Fatalf("other client: %d", rec.Code)
	}
}

func TestReadLimitCoversMetaAndRevealAndRunsBeforeBurn(t *testing.T) {
	store := testStore(t)
	cfg := testConfig()
	cfg.readLimit = 2
	h := newServer(cfg, store).routes()
	if err := store.Save(context.Background(), "abc", "opaque", time.Minute); err != nil {
		t.Fatal(err)
	}
	const attacker = "198.51.100.20:5000"
	if rec := do(t, h, request{method: http.MethodGet, path: "/api/secret/abc/meta", remote: attacker}); rec.Code != http.StatusOK {
		t.Fatalf("meta: %d", rec.Code)
	}
	if rec := do(t, h, request{method: http.MethodPost, path: "/api/secret/nope/reveal", remote: attacker, reveal: true}); rec.Code != http.StatusNotFound {
		t.Fatalf("miss: %d", rec.Code)
	}
	rec := do(t, h, request{method: http.MethodPost, path: "/api/secret/abc/reveal", remote: attacker, reveal: true})
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("third read: %d Retry-After=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
	// The rejected reveal must not have burned the secret.
	rec = do(t, h, request{method: http.MethodPost, path: "/api/secret/abc/reveal", remote: "198.51.100.21:5000", reveal: true})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "opaque") {
		t.Fatalf("legit reveal: %d %s", rec.Code, rec.Body)
	}
}

// ---- client IP trust ----

func TestSpoofedHeaderFromNonLoopbackPeerIsIgnored(t *testing.T) {
	cfg := testConfig()
	cfg.readLimit = 3
	h := newServer(cfg, testStore(t)).routes()
	for i := 0; i < 3; i++ {
		// A different forged client IP on every request: all from one real peer.
		rec := do(t, h, request{method: http.MethodGet, path: "/api/secret/x/meta", remote: "192.168.100.50:6000", cfIP: "203.0.113." + strconv.Itoa(i+1)})
		if rec.Code != http.StatusNotFound {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	rec := do(t, h, request{method: http.MethodGet, path: "/api/secret/x/meta", remote: "192.168.100.50:6000", cfIP: "203.0.113.99"})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed header bypassed the limit: %d", rec.Code)
	}
}

func TestLoopbackPeerHeaderIsHonoured(t *testing.T) {
	cfg := testConfig()
	cfg.readLimit = 1
	h := newServer(cfg, testStore(t)).routes()
	meta := func(remote, cf string) int {
		return do(t, h, request{method: http.MethodGet, path: "/api/secret/x/meta", remote: remote, cfIP: cf}).Code
	}
	if c := meta("127.0.0.1:40000", "203.0.113.10"); c != http.StatusNotFound {
		t.Fatalf("first: %d", c)
	}
	if c := meta("127.0.0.1:40001", "203.0.113.10"); c != http.StatusTooManyRequests {
		t.Fatalf("same tunnelled client: %d", c)
	}
	// A different visitor behind the same tunnel has its own budget, also via ::1.
	if c := meta("[::1]:40002", "203.0.113.11"); c != http.StatusNotFound {
		t.Fatalf("other tunnelled client: %d", c)
	}
}

func TestClientAddr(t *testing.T) {
	trusted, _ := parseTrustedProxies(defaultTrustedProxies)
	cases := []struct {
		name, remote, cf, xff, want string
	}{
		{"direct, no header", "198.51.100.1:1234", "", "", "198.51.100.1"},
		{"direct, forged header", "198.51.100.1:1234", "203.0.113.9", "", "198.51.100.1"},
		{"loopback v4 honours header", "127.0.0.1:1234", "203.0.113.9", "", "203.0.113.9"},
		{"loopback v6 honours header", "[::1]:1234", "2001:db8::7", "", "2001:db8::7"},
		{"v4-mapped loopback is loopback", "[::ffff:127.0.0.1]:1234", "203.0.113.9", "", "203.0.113.9"},
		{"loopback, garbage header", "127.0.0.1:1234", "not-an-ip", "", "127.0.0.1"},
		{"loopback, no header", "127.0.0.1:1234", "", "", "127.0.0.1"},
		{"X-Forwarded-For is never used", "127.0.0.1:1234", "", "203.0.113.9", "127.0.0.1"},
		{"X-Forwarded-For from direct peer", "198.51.100.1:1234", "", "203.0.113.9", "198.51.100.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = c.remote
			if c.cf != "" {
				r.Header.Set("CF-Connecting-IP", c.cf)
			}
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			if got := clientAddr(r, trusted); got != netip.MustParseAddr(c.want) {
				t.Fatalf("got %v want %s", got, c.want)
			}
		})
	}
}

func TestClientBucketGroupsIPv6By64(t *testing.T) {
	a := clientBucket(netip.MustParseAddr("2001:db8:1:2::1"))
	b := clientBucket(netip.MustParseAddr("2001:db8:1:2:ffff::9"))
	c := clientBucket(netip.MustParseAddr("2001:db8:1:3::1"))
	if a != b || a == c {
		t.Fatalf("buckets %q %q %q", a, b, c)
	}
	if clientBucket(netip.MustParseAddr("192.0.2.1")) == clientBucket(netip.MustParseAddr("192.0.2.2")) {
		t.Fatal("IPv4 addresses must not share a bucket")
	}
}

func TestParseTrustedProxies(t *testing.T) {
	got, err := parseTrustedProxies(" 127.0.0.0/8, ::1 ,172.17.0.1")
	if err != nil || len(got) != 3 || !inPrefixes(netip.MustParseAddr("127.9.9.9"), got) || !inPrefixes(netip.MustParseAddr("::1"), got) || !inPrefixes(netip.MustParseAddr("172.17.0.1"), got) {
		t.Fatalf("got %v err %v", got, err)
	}
	if inPrefixes(netip.MustParseAddr("172.17.0.2"), got) {
		t.Fatal("a bare IP must trust only itself")
	}
	if _, err := parseTrustedProxies("127.0.0.1,localhost"); err == nil {
		t.Fatal("hostnames must be rejected")
	}
}

// ---- Redis down ----

func TestRedisDownCreateFailsOpenReadFailsClosed(t *testing.T) {
	s := newServer(testConfig(), deadStore(t))
	var called atomic.Int32
	next := func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}

	rec := do(t, s.rateLimited(s.createLimiter, next), createReq("198.51.100.1:1", ""))
	if rec.Code != http.StatusNoContent || called.Load() != 1 {
		t.Fatalf("create should fail open: %d called=%d", rec.Code, called.Load())
	}

	rec = do(t, s.rateLimited(s.readLimiter, next), request{method: http.MethodPost, path: "/api/secret/x/reveal", remote: "198.51.100.1:1", reveal: true})
	if rec.Code != http.StatusServiceUnavailable || called.Load() != 1 {
		t.Fatalf("read should fail closed: %d called=%d", rec.Code, called.Load())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("fail-closed response needs Retry-After")
	}
}

func TestDisabledLimiterNeverTouchesRedis(t *testing.T) {
	cfg := testConfig()
	cfg.readLimit = 0
	s := newServer(cfg, deadStore(t))
	next := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	if rec := do(t, s.rateLimited(s.readLimiter, next), request{method: http.MethodGet, path: "/", remote: "198.51.100.1:1"}); rec.Code != http.StatusNoContent {
		t.Fatalf("disabled limiter: %d", rec.Code)
	}
}

// ---- /healthz ----

func healthz(t *testing.T, store *Store) (int, map[string]string, time.Duration) {
	t.Helper()
	h := newServer(testConfig(), store).routes()
	start := time.Now()
	rec := do(t, h, request{method: http.MethodGet, path: "/healthz", remote: "127.0.0.1:1"})
	elapsed := time.Since(start)
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return rec.Code, body, elapsed
}

func TestHealthzOKWhenRedisAnswers(t *testing.T) {
	code, body, _ := healthz(t, testStore(t))
	if code != http.StatusOK || body["status"] != "ok" || len(body) != 1 {
		t.Fatalf("%d %v", code, body)
	}
}

func TestHealthz503WhenRedisIsDown(t *testing.T) {
	code, body, _ := healthz(t, deadStore(t))
	if code != http.StatusServiceUnavailable || body["status"] == "ok" {
		t.Fatalf("%d %v", code, body)
	}
}

func TestHealthz503WithinTimeoutWhenRedisHangs(t *testing.T) {
	// Accepts connections and never answers, like a stopped Redis process.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	store := newStoreWithOptions(&redis.Options{Addr: ln.Addr().String(), MaxRetries: -1})
	t.Cleanup(func() { _ = store.Close() })

	code, _, elapsed := healthz(t, store)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", code)
	}
	if elapsed > healthPingTimeout+time.Second {
		t.Fatalf("health check took %v, want about %v", elapsed, healthPingTimeout)
	}
}
