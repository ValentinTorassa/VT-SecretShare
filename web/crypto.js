// Client-side AES-256-GCM. This file is the whole reason the service is
// "zero-knowledge": the key is generated, used, and kept here in the browser.
// The server never receives it. Wire format of the ciphertext blob:
//   base64( iv[12 bytes] || aes-gcm-ciphertext-with-tag )
// The key is exported raw and base64url-encoded to live in the URL #fragment.

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
