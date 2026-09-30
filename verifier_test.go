package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// newVerifier returns a random 32-byte verifier encoded as the browser sends it.
func newVerifier(t *testing.T) (string, []byte) {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b), b
}

func revealReq(remote, id, body string) request {
	return request{method: http.MethodPost, path: "/api/secret/" + id + "/reveal", remote: remote, reveal: true, body: body}
}

// The whole point of the verifier: a wrong key (or none) gets 403 wrong_key and
// the secret survives, the right key burns it exactly once.
func TestRevealWithWrongKeyKeepsTheSecret(t *testing.T) {
	store := testStore(t)
	h := newServer(testConfig(), store).routes()
	const client = "198.51.100.40:7000"
	good, goodBytes := newVerifier(t)
	wrong, _ := newVerifier(t)
	ct := base64.StdEncoding.EncodeToString([]byte("opaque"))
	rec := do(t, h, request{method: http.MethodPost, path: "/api/secret", remote: client,
		body: `{"ciphertext":"` + ct + `","verifier_hash":"` + verifierHash(goodBytes) + `"}`})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %d: %s", rec.Code, rec.Body)
	}
	var created createResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"wrong verifier": `{"verifier":"` + wrong + `"}`,
		"no body":        "",
		"no verifier":    `{}`,
	} {
		rec := do(t, h, revealReq(client, created.ID, body))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d want 403: %s", name, rec.Code, rec.Body)
		}
		var resp map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["code"] != "wrong_key" {
			t.Fatalf("%s: body %s", name, rec.Body)
		}
		if meta := do(t, h, request{method: http.MethodGet, path: "/api/secret/" + created.ID + "/meta", remote: client}); meta.Code != http.StatusOK {
			t.Fatalf("%s: secret gone (meta %d)", name, meta.Code)
		}
	}
	rec = do(t, h, revealReq(client, created.ID, `{"verifier":"`+good+`"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("right key: %d %s", rec.Code, rec.Body)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got["ciphertext"] != ct {
		t.Fatalf("ciphertext %q err %v", got["ciphertext"], err)
	}
	if rec := do(t, h, revealReq(client, created.ID, `{"verifier":"`+good+`"}`)); rec.Code != http.StatusNotFound {
		t.Fatalf("second reveal %d", rec.Code)
	}
}

// Secrets created without a verifier (old clients, curl) still reveal with an
// empty body, the way they did before verifiers existed.
func TestRevealWithoutVerifierBurnsLegacySecret(t *testing.T) {
	store := testStore(t)
	h := newServer(testConfig(), store).routes()
	if err := store.Save(context.Background(), "legacy", "b3BhcXVl", "", time.Minute); err != nil {
		t.Fatal(err)
	}
	if rec := do(t, h, revealReq("198.51.100.41:7000", "legacy", "")); rec.Code != http.StatusOK {
		t.Fatalf("legacy reveal %d: %s", rec.Code, rec.Body)
	}
}

// Malformed input is refused before Redis is touched, so it can never burn.
func TestMalformedVerifierInputIsRejected(t *testing.T) {
	store := testStore(t)
	h := newServer(testConfig(), store).routes()
	const client = "198.51.100.42:7000"
	_, goodBytes := newVerifier(t)
	if err := store.Save(context.Background(), "kept", "b3BhcXVl", verifierHash(goodBytes), time.Minute); err != nil {
		t.Fatal(err)
	}
	ct := base64.StdEncoding.EncodeToString([]byte("opaque"))
	cases := []struct {
		name   string
		rq     request
		status int
	}{
		{"short verifier_hash", request{method: http.MethodPost, path: "/api/secret", remote: client, body: `{"ciphertext":"` + ct + `","verifier_hash":"abc"}`}, http.StatusBadRequest},
		{"padded verifier_hash", request{method: http.MethodPost, path: "/api/secret", remote: client, body: `{"ciphertext":"` + ct + `","verifier_hash":"` + base64.URLEncoding.EncodeToString(goodBytes) + `"}`}, http.StatusBadRequest},
		{"short verifier", revealReq(client, "kept", `{"verifier":"abc"}`), http.StatusBadRequest},
		{"bad reveal json", revealReq(client, "kept", `{`), http.StatusBadRequest},
	}
	for _, c := range cases {
		if rec := do(t, h, c.rq); rec.Code != c.status {
			t.Fatalf("%s: %d want %d: %s", c.name, rec.Code, c.status, rec.Body)
		}
	}
	if _, err := store.TTL(context.Background(), "kept"); err != nil {
		t.Fatalf("secret burned by malformed input: %v", err)
	}
}
