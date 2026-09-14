import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {webcrypto} from 'node:crypto';
const api=runInNewContext(readFileSync(new URL('../web/crypto.js',import.meta.url),'utf8')+';({vtEncrypt,vtDecrypt,vtValidKeyFragment})',{crypto:webcrypto,TextEncoder,TextDecoder,Uint8Array,btoa,atob});
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
