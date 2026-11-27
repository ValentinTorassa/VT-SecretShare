package secretshare

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Produced by web/crypto.js (vtEncrypt, vtVerifier, vtVerifierHash) under
// Node, with a throwaway key. If this stops decrypting, links made in the
// browser no longer open from the command line. tests/crypto.test.mjs holds
// the mirror image: a vector made here that the browser code must open.
const (
	webPlaintext    = "Mensaje privado 🔒 — áéí\nsegunda línea"
	webCiphertext   = "JMieXb5yM4ZZuaRlkpnNsC56rW3i+qIi/rL3NDV4PvRamSpdZbxcW1dqKQJrN847cTWEXDsP+PhKqChXZDNk7ViwvDj6TYAMXVs="
	webKey          = "K0Fda1L57KkR65fmw68OFj8RxfqL1nw9hngqPtV_2d8"
	webVerifier     = "QHBFir7nCg0opq_84eh5c7-yCXzZE2wN_We-05SXIrE"
	webVerifierHash = "ze9FOfhA3dAGatdBRQ6HKTI38gu5Uf2wNGxT-MJ_VZM"
)

func TestOpensWhatTheBrowserEncrypted(t *testing.T) {
	got, err := Decrypt(webCiphertext, webKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != webPlaintext {
		t.Fatalf("plaintext %q", got)
	}
}

func TestVerifierMatchesTheBrowser(t *testing.T) {
	v, err := Verifier(webKey)
	if err != nil || v != webVerifier {
		t.Fatalf("verifier %q, %v", v, err)
	}
	h, err := VerifierHash(webKey)
	if err != nil || h != webVerifierHash {
		t.Fatalf("verifier hash %q, %v", h, err)
	}
}

func TestRoundTripAndFreshKeys(t *testing.T) {
	for _, text := range []string{"x", "Mensaje privado 🔒 — áéí", strings.Repeat("k", 5000)} {
		ct, key, err := Encrypt([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		if !ValidKey(key) {
			t.Fatalf("key %q is not valid", key)
		}
		got, err := Decrypt(ct, key)
		if err != nil || string(got) != text {
			t.Fatalf("round trip: %q, %v", got, err)
		}
	}
	a, ka, _ := Encrypt([]byte("same"))
	b, kb, _ := Encrypt([]byte("same"))
	if a == b || ka == kb {
		t.Fatal("two encryptions shared a key or a ciphertext")
	}
}

func TestTamperedCiphertextAndWrongKeyAreRejected(t *testing.T) {
	ct, key, _ := Encrypt([]byte("synthetic"))
	_, other, _ := Encrypt([]byte("other"))
	if _, err := Decrypt(ct, other); err == nil {
		t.Fatal("wrong key decrypted")
	}
	blob, _ := base64.StdEncoding.DecodeString(ct)
	blob[len(blob)-1] ^= 1
	if _, err := Decrypt(base64.StdEncoding.EncodeToString(blob), key); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
	if _, err := Decrypt("AA==", key); err == nil {
		t.Fatal("truncated ciphertext decrypted")
	}
}

func TestValidKey(t *testing.T) {
	for _, bad := range []string{"", "short", strings.Repeat("a", 44), strings.Repeat("?", 43), webKey[:42]} {
		if ValidKey(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if !ValidKey(webKey) {
		t.Error("a real key was rejected")
	}
}

func TestParseLink(t *testing.T) {
	const id = "r2gi1se4a5hYWNSAunvPCQ"
	cases := []struct {
		raw     string
		needKey bool
		want    Link
	}{
		{"https://secretshare.example.com/s/" + id + "#" + webKey, true, Link{"https://secretshare.example.com", id, webKey}},
		// links made before v1.1 carried the sender's theme and language
		{"https://secretshare.example.com/s/" + id + "?theme=pro&lang=en#" + webKey, true, Link{"https://secretshare.example.com", id, webKey}},
		{"http://localhost:8080/s/" + id + "#" + webKey, true, Link{"http://localhost:8080", id, webKey}},
		{"  https://host.example/base/s/" + id + "#" + webKey + "\n", true, Link{"https://host.example/base", id, webKey}},
		{"https://secretshare.example.com/s/" + id, false, Link{"https://secretshare.example.com", id, ""}},
	}
	for _, c := range cases {
		got, err := ParseLink(c.raw, c.needKey)
		if err != nil || got != c.want {
			t.Errorf("ParseLink(%q) = %+v, %v; want %+v", c.raw, got, err, c.want)
		}
	}
	for _, bad := range []string{
		"", "not a link", "ftp://host/s/" + id + "#" + webKey, "https://host/" + id + "#" + webKey,
		"https://host/s/#" + webKey, "https://host/s/a b#" + webKey,
		"https://host/s/" + id,                     // no key
		"https://host/s/" + id + "#" + webKey[:20], // cut short while copying
	} {
		if got, err := ParseLink(bad, true); err == nil {
			t.Errorf("ParseLink(%q) accepted: %+v", bad, got)
		}
	}
	l := Link{"https://host.example", id, webKey}
	if back, err := ParseLink(l.String(), true); err != nil || back != l {
		t.Errorf("String/ParseLink round trip: %+v, %v", back, err)
	}
}

// The largest plaintext must still fit the server's default ciphertext limit
// (256 KiB of base64) once the IV and the tag are added.
func TestMaxPlaintextFitsTheServerLimit(t *testing.T) {
	ct, _, err := Encrypt(make([]byte, MaxPlaintext))
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) > 256*1024 {
		t.Fatalf("ciphertext of the largest plaintext is %d bytes", len(ct))
	}
	ct, _, _ = Encrypt(make([]byte, MaxPlaintext+1))
	if len(ct) <= 256*1024 {
		t.Fatalf("MaxPlaintext could be larger: %d bytes still fit", MaxPlaintext+1)
	}
}
