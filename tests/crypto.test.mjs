import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {webcrypto,hkdfSync,createHash} from 'node:crypto';
const api=runInNewContext(readFileSync(new URL('../web/crypto.js',import.meta.url),'utf8')+';({vtEncrypt,vtDecrypt,vtValidKeyFragment,vtVerifier,vtVerifierHash})',{crypto:webcrypto,TextEncoder,TextDecoder,Uint8Array,btoa,atob});
test('Unicode and empty plaintext round trip',async()=>{
 for(const text of ['', 'Mensaje privado 🔒 — áéí']) {const encrypted=await api.vtEncrypt(text);assert.equal(await api.vtDecrypt(encrypted.ciphertext,encrypted.keyFragment),text);assert.equal(api.vtValidKeyFragment(encrypted.keyFragment),true);}
});
test('same plaintext receives fresh key and ciphertext',async()=>{
 const a=await api.vtEncrypt('synthetic'),b=await api.vtEncrypt('synthetic');assert.notEqual(a.keyFragment,b.keyFragment);assert.notEqual(a.ciphertext,b.ciphertext);
});
test('tampered ciphertext and wrong keys are rejected',async()=>{
 const a=await api.vtEncrypt('synthetic'),b=await api.vtEncrypt('other');
 const bytes=Buffer.from(a.ciphertext,'base64');bytes[bytes.length-1]^=1;
 await assert.rejects(api.vtDecrypt(bytes.toString('base64'),a.keyFragment));
 await assert.rejects(api.vtDecrypt(a.ciphertext,b.keyFragment));
});
test('malformed fragment and truncated ciphertext are rejected',async()=>{
 for(const value of ['', 'short', 'a'.repeat(44), '?'.repeat(43)]) assert.equal(api.vtValidKeyFragment(value),false);
 const a=await api.vtEncrypt('synthetic');await assert.rejects(api.vtDecrypt('AA==',a.keyFragment));
});
const b64url=b=>Buffer.from(b).toString('base64url');
test('reveal verifier is HKDF-SHA256 of the key, and the create hash is SHA-256 of it',async()=>{
 const {keyFragment}=await api.vtEncrypt('synthetic');
 const expected=b64url(hkdfSync('sha256',Buffer.from(keyFragment,'base64url'),Buffer.alloc(0),'vt-secretshare/reveal-verifier/v1',32));
 const verifier=await api.vtVerifier(keyFragment);
 assert.equal(verifier,expected);
 assert.notEqual(verifier,keyFragment);
 assert.equal(await api.vtVerifierHash(keyFragment),b64url(createHash('sha256').update(Buffer.from(verifier,'base64url')).digest()));
 assert.match(verifier,/^[A-Za-z0-9_-]{43}$/);
});
test('different keys give different verifiers',async()=>{
 const a=await api.vtEncrypt('x'),b=await api.vtEncrypt('x');
 assert.notEqual(await api.vtVerifier(a.keyFragment),await api.vtVerifier(b.keyFragment));
});
