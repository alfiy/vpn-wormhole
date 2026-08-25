/**
 * Simple Node.js test for the key derivation + AES-GCM logic
 * (mirrors the browser Web Crypto flow using Node crypto)
 */

const crypto = require('crypto');
const { webcrypto } = require('crypto');

async function deriveKey(code) {
  const enc = new TextEncoder();
  const keyMaterial = await webcrypto.subtle.importKey(
    'raw',
    enc.encode(code),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return webcrypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: enc.encode('vpn-wormhole-v1-salt'),
      iterations: 210000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true, // extractable for test
    ['encrypt', 'decrypt']
  );
}

async function encrypt(key, obj) {
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(obj));
  const ciphertext = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext
  );
  return { iv: Buffer.from(iv).toString('base64'), ct: Buffer.from(ciphertext).toString('base64') };
}

async function decrypt(key, payload) {
  const iv = Buffer.from(payload.iv, 'base64');
  const ct = Buffer.from(payload.ct, 'base64');
  const plaintext = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ct
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

(async () => {
  const code = '7-apple-river';
  console.log('Testing with code:', code);

  const key1 = await deriveKey(code);
  const key2 = await deriveKey(code);

  // Same code must produce same key
  const raw1 = await webcrypto.subtle.exportKey('raw', key1);
  const raw2 = await webcrypto.subtle.exportKey('raw', key2);
  const same = Buffer.from(raw1).equals(Buffer.from(raw2));
  console.log('Keys match:', same ? 'PASS' : 'FAIL');

  const msg = { type: 'chat', text: '你好，VPN-Wormhole!' };
  const sealed = await encrypt(key1, msg);
  const opened = await decrypt(key2, sealed);
  console.log('Round-trip message:', JSON.stringify(opened) === JSON.stringify(msg) ? 'PASS' : 'FAIL');
  console.log('Decrypted content:', opened);

  // Wrong code should fail
  try {
    const badKey = await deriveKey('wrong-code');
    await decrypt(badKey, sealed);
    console.log('Wrong key rejected: FAIL (should have thrown)');
  } catch (e) {
    console.log('Wrong key rejected: PASS');
  }

  console.log('\nAll crypto tests finished.');
})();
