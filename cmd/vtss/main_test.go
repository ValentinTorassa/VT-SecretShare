package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// What the command reads and writes, against an in-memory stand-in for the
// API. The client against the real handlers is tested in ../../client_test.go.

type fakeServer struct {
	*httptest.Server
	mu      sync.Mutex
	secrets map[string][2]string // id -> ciphertext, verifier hash
	lastTTL int
}

func newFake(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{secrets: map[string][2]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/secret", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Ciphertext   string `json:"ciphertext"`
			TTLSeconds   int    `json:"ttl_seconds"`
			VerifierHash string `json:"verifier_hash"`
		}
		if r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		id := fmt.Sprintf("id%d", len(f.secrets)+1)
		f.secrets[id] = [2]string{req.Ciphertext, req.VerifierHash}
		f.lastTTL = req.TTLSeconds
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"id": id, "share_url": f.URL + "/s/" + id, "ttl_seconds": req.TTLSeconds,
			"expires_at": time.Now().UTC().Add(time.Duration(req.TTLSeconds) * time.Second).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("POST /api/secret/{id}/reveal", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Verifier string `json:"verifier"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		s, ok := f.secrets[r.PathValue("id")]
		if r.Header.Get("X-VT-Reveal") != "1" || !ok {
			http.Error(w, `{"error":"gone"}`, http.StatusNotFound)
			return
		}
		v, _ := base64.RawURLEncoding.DecodeString(req.Verifier)
		sum := sha256.Sum256(v)
		if base64.RawURLEncoding.EncodeToString(sum[:]) != s[1] {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"wrong key","code":"wrong_key"}`))
			return
		}
		delete(f.secrets, r.PathValue("id"))
		json.NewEncoder(w).Encode(map[string]string{"ciphertext": s[0]})
	})
	mux.HandleFunc("GET /api/secret/{id}/meta", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, ok := f.secrets[r.PathValue("id")]; !ok {
			http.Error(w, `{"error":"gone"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"alive": true, "ttl_seconds": 86399,
			"expires_at": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)})
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// vtss runs the command with stdin fed from a file (so it is not a terminal)
// and returns the exit code and what went to stdout and stderr.
func vtss(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	dir := t.TempDir()
	file := func(name, content string) *os.File {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(content)
		f.Seek(0, 0)
		t.Cleanup(func() { f.Close() })
		return f
	}
	in, out, errF := file("in", stdin), file("out", ""), file("err", "")
	code := run(args, in, out, errF)
	read := func(f *os.File) string {
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	return code, read(out), read(errF)
}

func send(t *testing.T, f *fakeServer, secret string) string {
	t.Helper()
	code, out, errOut := vtss(t, secret, "--server", f.URL)
	if code != exitOK {
		t.Fatalf("send: exit %d, stderr %q", code, errOut)
	}
	return strings.TrimSuffix(out, "\n")
}

func TestSendPrintsOnlyTheLinkAndOpenPrintsOnlyTheSecret(t *testing.T) {
	f := newFake(t)
	code, out, errOut := vtss(t, "s3cr3t\n", "--server", f.URL)
	if code != exitOK || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if !strings.HasPrefix(out, f.URL+"/s/id1#") || strings.Count(out, "\n") != 1 || strings.ContainsAny(out, "?& ") {
		t.Fatalf("stdout %q", out)
	}
	if f.lastTTL != 86400 {
		t.Errorf("default ttl sent: %d", f.lastTTL)
	}
	link := strings.TrimSuffix(out, "\n")

	code, out, errOut = vtss(t, "", "open", link)
	// echo's newline is dropped on the way in, and a pipe gets no extra one.
	if code != exitOK || out != "s3cr3t" || errOut != "" {
		t.Fatalf("open: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	code, out, errOut = vtss(t, "", "open", link)
	if code != exitGone || out != "" || !strings.Contains(errOut, "gone") {
		t.Fatalf("second open: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestSendKeepsInnerNewlinesAndReadsTheServerFromTheEnvironment(t *testing.T) {
	f := newFake(t)
	t.Setenv("VTSS_SERVER", f.URL)
	const env = "A=1\nB=2\n\n"
	code, out, errOut := vtss(t, env, "-t", "10m")
	if code != exitOK {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if f.lastTTL != 600 {
		t.Errorf("ttl sent: %d", f.lastTTL)
	}
	_, got, _ := vtss(t, "", "open", strings.TrimSpace(out))
	if got != "A=1\nB=2\n" { // only the last newline goes
		t.Fatalf("secret %q", got)
	}
}

func TestOpenToAFileNeverPrintsTheSecret(t *testing.T) {
	f := newFake(t)
	for _, order := range []string{"flag first", "link first"} {
		link := send(t, f, "token-123")
		target := filepath.Join(t.TempDir(), "secret.env")
		args := []string{"open", "-o", target, link}
		if order == "link first" {
			args = []string{"open", link, "--output", target}
		}
		code, out, errOut := vtss(t, "", args...)
		if code != exitOK || out != "" || strings.Contains(errOut, "token-123") {
			t.Fatalf("%s: exit %d, stdout %q, stderr %q", order, code, out, errOut)
		}
		got, err := os.ReadFile(target)
		if err != nil || string(got) != "token-123" {
			t.Fatalf("%s: file %q, %v", order, got, err)
		}
		if info, _ := os.Stat(target); info.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v", order, info.Mode().Perm())
		}
	}
}

// Opening deletes the secret, so a file that cannot be written must be found
// out before the request, and a link that is gone must not wipe a file.
func TestOpenToAFileDoesNotLoseAnything(t *testing.T) {
	f := newFake(t)
	link := send(t, f, "still-here")
	code, out, errOut := vtss(t, "", "open", link, "-o", filepath.Join(t.TempDir(), "no", "such", "dir", "x"))
	if code != exitError || out != "" || !strings.Contains(errOut, "not opened") {
		t.Fatalf("unwritable path: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if code, out, _ := vtss(t, "", "open", link); code != exitOK || out != "still-here" {
		t.Fatalf("the secret was burned by a failed -o: exit %d, %q", code, out)
	}

	existing := filepath.Join(t.TempDir(), "keep.txt")
	if err := os.WriteFile(existing, []byte("previous content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := vtss(t, "", "open", link, "-o", existing); code != exitGone {
		t.Fatalf("gone link with -o: exit %d", code)
	}
	if got, _ := os.ReadFile(existing); string(got) != "previous content" {
		t.Fatalf("a gone link wiped the file: %q", got)
	}
	fresh := filepath.Join(t.TempDir(), "new.txt")
	vtss(t, "", "open", link, "-o", fresh)
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatal("a gone link left an empty file behind")
	}
}

func TestWrongKeyKeepsTheSecretAndHasItsOwnExitCode(t *testing.T) {
	f := newFake(t)
	link := send(t, f, "intact")
	other := send(t, f, "other")
	wrong := link[:strings.Index(link, "#")] + other[strings.Index(other, "#"):]
	code, out, errOut := vtss(t, "", "open", wrong)
	if code != exitWrongKey || out != "" || !strings.Contains(errOut, "still there") {
		t.Fatalf("wrong key: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if code, out, _ := vtss(t, "", "open", link); code != exitOK || out != "intact" {
		t.Fatalf("right key afterwards: exit %d, %q", code, out)
	}
}

func TestStatusDoesNotOpen(t *testing.T) {
	f := newFake(t)
	link := send(t, f, "waiting")
	code, out, _ := vtss(t, "", "status", link)
	if code != exitOK || out != "unopened: expires in 1 day\n" {
		t.Fatalf("status: exit %d, %q", code, out)
	}
	// the key is not needed to ask
	code, out, _ = vtss(t, "", "status", "--json", link[:strings.Index(link, "#")])
	var st struct {
		Alive bool `json:"alive"`
		TTL   int  `json:"ttl_seconds"`
	}
	if code != exitOK || json.Unmarshal([]byte(out), &st) != nil || !st.Alive || st.TTL != 86399 {
		t.Fatalf("status --json: exit %d, %q", code, out)
	}
	vtss(t, "", "open", link)
	code, out, _ = vtss(t, "", "status", link)
	if code != exitGone || !strings.HasPrefix(out, "gone") {
		t.Fatalf("status after open: exit %d, %q", code, out)
	}
}

func TestJSONOutput(t *testing.T) {
	f := newFake(t)
	code, out, _ := vtss(t, "j", "--json", "--server", f.URL, "--ttl", "7d")
	var created struct {
		URL       string `json:"url"`
		ID        string `json:"id"`
		ExpiresAt string `json:"expires_at"`
		TTL       int    `json:"ttl_seconds"`
	}
	if code != exitOK || json.Unmarshal([]byte(out), &created) != nil {
		t.Fatalf("exit %d, %q", code, out)
	}
	if created.ID != "id1" || created.TTL != 604800 || !strings.Contains(created.URL, "/s/id1#") || created.ExpiresAt == "" {
		t.Fatalf("%+v", created)
	}
	// The # must survive as is: an escaped link would not open.
	if strings.Contains(out, `&`) || strings.Contains(out, `<`) {
		t.Fatalf("escaped JSON: %q", out)
	}
	code, out, _ = vtss(t, "", "open", created.URL, "--json")
	var opened struct {
		Secret string `json:"secret"`
	}
	if code != exitOK || json.Unmarshal([]byte(out), &opened) != nil || opened.Secret != "j" {
		t.Fatalf("open --json: exit %d, %q", code, out)
	}
}

func TestUsageErrors(t *testing.T) {
	f := newFake(t)
	cases := []struct {
		name  string
		stdin string
		args  []string
		want  string
	}{
		{"secret as an argument", "", []string{"hunter2"}, "read from stdin"},
		{"link without open", "", []string{"https://host.example/s/abc#" + strings.Repeat("A", 43)}, "vtss open"},
		{"empty secret", "\n", []string{"--server", f.URL}, "empty"},
		{"bad ttl", "x", []string{"--ttl", "soon"}, "--ttl"},
		{"bad server", "x", []string{"--server", "secretshare.example.com"}, "--server"},
		{"unknown flag", "x", []string{"--nope"}, "--help"},
		{"open without a link", "", []string{"open"}, "usage"},
		{"open a link without its key", "", []string{"open", "https://host.example/s/abc"}, "after #"},
		{"open something else", "", []string{"open", "hello"}, "not a share link"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errOut := vtss(t, c.stdin, c.args...)
			if code != exitUsage || out != "" || !strings.Contains(errOut, c.want) {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
			}
			if strings.Contains(errOut, "hunter2") && c.name != "secret as an argument" {
				t.Fatal("stderr repeats input it should not")
			}
		})
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.secrets) != 0 {
		t.Fatalf("a usage error still created %d secret(s)", len(f.secrets))
	}
}

func TestHelpAndVersion(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		code, out, _ := vtss(t, "", arg)
		if code != exitOK || !strings.Contains(out, "vtss open <link>") || !strings.Contains(out, "Exit codes") {
			t.Fatalf("%s: exit %d, %q", arg, code, out)
		}
	}
	if code, out, _ := vtss(t, "", "open", "--help"); code != exitOK || !strings.Contains(out, "Usage:") {
		t.Fatalf("open --help: exit %d, %q", code, out)
	}
	if code, out, _ := vtss(t, "", "--version"); code != exitOK || !strings.HasPrefix(out, "vtss ") {
		t.Fatalf("--version: exit %d, %q", code, out)
	}
}

func TestParseTTL(t *testing.T) {
	good := map[string]time.Duration{
		"10m": 10 * time.Minute, "1h": time.Hour, "1d": 24 * time.Hour, "7d": 7 * 24 * time.Hour,
		"90s": 90 * time.Second, "600": 10 * time.Minute, " 1D ": 24 * time.Hour, "1h30m": 90 * time.Minute,
	}
	for in, want := range good {
		if got, err := parseTTL(in); err != nil || got != want {
			t.Errorf("parseTTL(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "soon", "0", "-5m", "0d", "d", "1w"} {
		if got, err := parseTTL(bad); err == nil {
			t.Errorf("parseTTL(%q) accepted: %v", bad, got)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	cases := map[time.Duration]string{
		10 * time.Minute:                "10 minutes",
		time.Minute:                     "1 minute",
		time.Hour:                       "1 hour",
		59*time.Minute + 58*time.Second: "1 hour",
		24 * time.Hour:                  "1 day",
		24*time.Hour - time.Second:      "1 day",
		7 * 24 * time.Hour:              "7 days",
		7*24*time.Hour - time.Second:    "7 days",
		5 * time.Hour:                   "5 hours",
		45 * time.Second:                "45 seconds",
	}
	for d, want := range cases {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestTrimOneNewline(t *testing.T) {
	cases := map[string]string{"abc\n": "abc", "abc\r\n": "abc", "abc\n\n": "abc\n", "abc": "abc", "": "", "\n": "", "a\nb": "a\nb"}
	for in, want := range cases {
		if got := string(trimOneNewline([]byte(in))); got != want {
			t.Errorf("trimOneNewline(%q) = %q, want %q", in, got, want)
		}
	}
}
