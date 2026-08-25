/**
 * SPAKE2 (RFC 9382 style) over RFC 3526 2048-bit MODP group — pure JS/BigInt
 * Balanced PAKE for two peers sharing a low-entropy password (room code).
 *
 * Protocol (one round-trip):
 *   A: start() -> msgA ; B: start() -> msgB
 *   A: finish(msgB) -> key ; B: finish(msgA) -> key
 * Both sides get the same 32-byte key material for HKDF → AES-GCM.
 */
(function (global) {
  'use strict';

  // RFC 3526 2048-bit MODP Group (group 14)
  const P = BigInt(
    '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
    '15728E5A8AACAA68FFFFFFFFFFFFFFFF'
  );
  const G = 2n;
  // Order of the subgroup is (P-1)/2 for safe prime; we work mod P carefully
  const Q = (P - 1n) / 2n;

  // M, N = G^c mod P with fixed non-secret constants (ensures subgroup membership)
  // Derived from domain-separated seeds (not passwords)
  const M_EXP = BigInt('0x' + 'a5c2d6e8f1a3b5079c4e2d1f8b6a9037e4d5c6b7a8091f2e3d4c5b6a79807f6e');
  const N_EXP = BigInt('0x' + 'b6d3e7f9a2b4c6180d5f3e2a9c7b0148f5e6d7c8b91a2f3d4e5f6a7b8c91a0f8');
  // Lazy init after modPow is defined
  let M = null;
  let N = null;
  function ensureMN() {
    if (M === null) {
      M = modPow(G, M_EXP % Q, P);
      N = modPow(G, N_EXP % Q, P);
    }
  }

  function modPow(base, exp, mod) {
    let result = 1n;
    base = ((base % mod) + mod) % mod;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      base = (base * base) % mod;
      exp >>= 1n;
    }
    return result;
  }

  function modInv(a, mod) {
    // Fermat: a^(mod-2) for prime mod
    return modPow(a, mod - 2n, mod);
  }

  function bytesToBigInt(bytes) {
    let x = 0n;
    for (let i = 0; i < bytes.length; i++) {
      x = (x << 8n) | BigInt(bytes[i]);
    }
    return x;
  }

  function bigIntToBytes(n, len) {
    const out = new Uint8Array(len);
    let x = n;
    for (let i = len - 1; i >= 0; i--) {
      out[i] = Number(x & 0xffn);
      x >>= 8n;
    }
    return out;
  }

  function concatBytes(...arrs) {
    let total = 0;
    for (const a of arrs) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrs) {
      out.set(a, off);
      off += a.length;
    }
    return out;
  }

  async function sha256(data) {
    const hash = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hash);
  }

  /** Password → scalar in [1, Q) */
  async function passwordToScalar(passwordBytes, side) {
    const enc = new TextEncoder();
    const input = concatBytes(
      enc.encode('vpn-wormhole-spake2-v1:'),
      passwordBytes,
      enc.encode(':' + side)
    );
    // Stretch a bit so offline attempts are slower even against the PAKE transcript
    let h = await sha256(input);
    for (let i = 0; i < 1000; i++) {
      h = await sha256(concatBytes(h, input));
    }
    let w = bytesToBigInt(h) % Q;
    if (w === 0n) w = 1n;
    return w;
  }

  function randomScalar() {
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    let x = bytesToBigInt(buf) % Q;
    if (x === 0n) x = 1n;
    return x;
  }

  /**
   * @param {string|Uint8Array} password room code
   * @param {'A'|'B'} side creator=A, joiner=B
   */
  function createSPAKE2(password, side) {
    if (side !== 'A' && side !== 'B') throw new Error('side must be A or B');
    const pwBytes =
      typeof password === 'string'
        ? new TextEncoder().encode(password)
        : password;

    let x = null; // secret scalar
    let w = null; // password scalar
    let myMsg = null;
    let finished = false;

    return {
      side,
      async start() {
        ensureMN();
        w = await passwordToScalar(pwBytes, 'shared');
        x = randomScalar();
        const X = modPow(G, x, P); // g^x
        // A: pA = g^x * M^w ; B: pB = g^x * N^w
        const blind = side === 'A' ? modPow(M, w, P) : modPow(N, w, P);
        const p = (X * blind) % P;
        myMsg = bigIntToBytes(p, 256);
        return myMsg;
      },

      /**
       * @param {Uint8Array} peerMsg
       * @returns {Promise<Uint8Array>} 32-byte shared key material
       */
      async finish(peerMsg) {
        if (finished) throw new Error('already finished');
        if (!x || w === null || !myMsg) throw new Error('call start() first');
        if (!(peerMsg instanceof Uint8Array) || peerMsg.length < 32) {
          throw new Error('invalid peer message');
        }

        const peer = bytesToBigInt(peerMsg) % P;
        if (peer <= 1n || peer >= P - 1n) throw new Error('invalid peer element');

        // Remove password blind from peer message
        // A receives pB = g^y * N^w  →  g^y = pB * (N^w)^-1
        // B receives pA = g^x * M^w  →  g^x = pA * (M^w)^-1
        const peerBlind = side === 'A' ? modPow(N, w, P) : modPow(M, w, P);
        const peerUnblinded = (peer * modInv(peerBlind, P)) % P;

        // K = (g^{peer})^x = g^{xy}
        const K = modPow(peerUnblinded, x, P);
        const kBytes = bigIntToBytes(K, 256);

        // Transcript must be identical on both sides: always msgA || msgB
        const peerFixed = peerMsg.length >= 256 ? peerMsg.subarray(0, 256) : peerMsg;
        const msgA = side === 'A' ? myMsg : peerFixed;
        const msgB = side === 'A' ? peerFixed : myMsg;
        const enc = new TextEncoder();
        const transcript = concatBytes(
          enc.encode('vpn-wormhole-spake2-finish-v1'),
          msgA,
          msgB,
          kBytes,
          pwBytes
        );
        const keyMaterial = await sha256(transcript);
        finished = true;
        // wipe secrets
        x = null;
        w = null;
        return keyMaterial;
      }
    };
  }

  /**
   * Import 32-byte key material as AES-GCM CryptoKey via HKDF-SHA-256
   */
  async function keyMaterialToAesGcm(keyMaterial) {
    const baseKey = await crypto.subtle.importKey(
      'raw',
      keyMaterial,
      'HKDF',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new TextEncoder().encode('vpn-wormhole-aes-v1'),
        info: new TextEncoder().encode('aes-256-gcm')
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  function bytesToBase64(u8) {
    let s = '';
    const chunk = 0x8000;
    for (let i = 0; i < u8.length; i += chunk) {
      s += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
    }
    return btoa(s);
  }

  function base64ToBytes(b64) {
    const s = atob(b64);
    const u8 = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
    return u8;
  }

  global.SPAKE2 = {
    create: createSPAKE2,
    keyMaterialToAesGcm,
    bytesToBase64,
    base64ToBytes
  };
})(typeof window !== 'undefined' ? window : globalThis);
