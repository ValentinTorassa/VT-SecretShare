// Client-side AES-256-GCM. This file is the whole reason the service is
// "zero-knowledge": the key is generated, used, and kept here in the browser.
// The server never receives it. Wire format of the ciphertext blob:
//   base64( iv[12 bytes] || aes-gcm-ciphertext-with-tag )
// The key is exported raw and base64url-encoded to live in the URL #fragment.
//
// Reveal verifier: HKDF-SHA256 over the raw key (info below) gives 32 bytes
// that prove the reveal holds the key without revealing it (HKDF output for a
// different info is unrelated to the key). The server gets SHA-256(verifier)
// on create and the verifier itself on reveal, and only burns the secret when
// they match, so a mistyped or truncated link no longer destroys it.
const VT_VERIFIER_INFO = "vt-secretshare/reveal-verifier/v1";

function bytesToB64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function b64ToBytes(str) {
  const s = atob(str);
  const a = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
  return a;
}
function bytesToB64url(bytes) {
  return bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBytes(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return b64ToBytes(str);
}

function vtValidKeyFragment(keyFragment) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(keyFragment)) return false;
  try { return b64urlToBytes(keyFragment).length === 32; }
  catch (_) { return false; }
}

// vtEncrypt -> { ciphertext (base64), keyFragment (base64url) }
async function vtEncrypt(plaintext) {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext)
  );
  const ct = new Uint8Array(ctBuf);
  const blob = new Uint8Array(iv.length + ct.length);
  blob.set(iv, 0);
  blob.set(ct, iv.length);
  const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  return { ciphertext: bytesToB64(blob), keyFragment: bytesToB64url(rawKey) };
}

// vtDecrypt(ciphertext base64, keyFragment base64url) -> plaintext string
async function vtDecrypt(ciphertextB64, keyFragment) {
  const blob = b64ToBytes(ciphertextB64);
  const iv = blob.slice(0, 12);
  const ct = blob.slice(12);
  const rawKey = b64urlToBytes(keyFragment);
  const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new TextDecoder().decode(ptBuf);
}

// vtVerifier(keyFragment base64url) -> verifier (base64url, 32 bytes)
async function vtVerifier(keyFragment) {
  const ikm = await crypto.subtle.importKey("raw", b64urlToBytes(keyFragment), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new TextEncoder().encode(VT_VERIFIER_INFO) },
    ikm,
    256
  );
  return bytesToB64url(new Uint8Array(bits));
}

// vtVerifierHash(keyFragment) -> base64url(SHA-256(verifier)), sent on create
async function vtVerifierHash(keyFragment) {
  const verifier = b64urlToBytes(await vtVerifier(keyFragment));
  return bytesToB64url(new Uint8Array(await crypto.subtle.digest("SHA-256", verifier)));
}
