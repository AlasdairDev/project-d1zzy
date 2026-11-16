/* D1zzy browser crypto. Mirrors app/core/crypto.py byte for byte.
 *
 * Identity: passphrase --Argon2id(salt = BLAKE2b("d1zzy-salt:" + email))--> 32-byte seed
 *           seed -> Ed25519 signing key -> X25519 exchange key (birational map)
 * Blobs:    24-byte nonce || XChaCha20-Poly1305(ciphertext + tag)
 * Sigs:     Ed25519 over context-prefix || data
 *
 * The passphrase and secret keys never leave the browser. The seed lives in sessionStorage
 * for the current tab session only; closing the browser locks the keys again.
 */
(function () {
  "use strict";
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const CONTEXTS = {
    listing: "d1zzy:listing:v1\0",
    offer: "d1zzy:offer:v1\0",
    rating: "d1zzy:rating:v1\0",
    report: "d1zzy:report:v1\0",
    keys: "d1zzy:keys:v1\0",
  };

  let S = null; // libsodium, once ready
  const ready = (self.sodium ? self.sodium.ready : Promise.reject(new Error("no sodium"))).then(
    () => {
      S = self.sodium;
      return S;
    }
  );

  const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) {
      out.set(p, o);
      o += p.length;
    }
    return out;
  };
  const b64e = (u8) => S.to_base64(u8, S.base64_variants.ORIGINAL);
  const b64d = (s) => S.from_base64(s, S.base64_variants.ORIGINAL);
  const utf8 = (s) => enc.encode(s);

  function seal(plaintext, key, ad) {
    const nonce = S.randombytes_buf(24);
    const ct = S.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad || null, null, nonce, key);
    return concat(nonce, ct);
  }

  function open(blob, key, ad) {
    if (blob.length < 40) throw new Error("ciphertext too short");
    return S.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, blob.subarray(24), ad || null, blob.subarray(0, 24), key
    );
  }

  // Python json.dumps(sort_keys=True, separators=(",", ":")) compatible.
  function canonical(v) {
    if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
    if (v && typeof v === "object") {
      return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
    }
    return JSON.stringify(v);
  }

  const signedMessage = (ctx, data) => concat(utf8(CONTEXTS[ctx]), data);
  const sign = (ctx, data, sk) => S.crypto_sign_detached(signedMessage(ctx, data), sk);
  function verify(ctx, data, sig, pk) {
    if (!pk || pk.length !== 32 || !sig || sig.length !== 64) return false;
    try {
      return S.crypto_sign_verify_detached(sig, signedMessage(ctx, data), pk);
    } catch (e) {
      return false;
    }
  }

  function salt(email) {
    return S.crypto_generichash(16, utf8("d1zzy-salt:" + email.trim().toLowerCase()), null);
  }

  function identityFromSeed(seed) {
    const kp = S.crypto_sign_seed_keypair(seed);
    const xsk = S.crypto_sign_ed25519_sk_to_curve25519(kp.privateKey);
    const psk = S.crypto_generichash(32, utf8("profile"), seed);
    return {
      seed,
      signingSk: kp.privateKey,
      signingPk: kp.publicKey,
      exchangeSk: xsk,
      exchangePk: S.crypto_scalarmult_base(xsk),
      profileSk: psk,
      profilePk: S.crypto_scalarmult_base(psk),
    };
  }

  function deriveIdentity(email, passphrase) {
    const seed = S.crypto_pwhash(
      32, utf8(passphrase), salt(email),
      S.crypto_pwhash_OPSLIMIT_INTERACTIVE, S.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      S.crypto_pwhash_ALG_ARGON2ID13
    );
    return identityFromSeed(seed);
  }

  // --- Server helpers ------------------------------------------------------------------

  const csrf = () => (document.querySelector('meta[name="csrf-token"]') || {}).content || "";

  async function api(method, url, body, isForm) {
    const headers = { "X-CSRF-Token": csrf(), Accept: "application/json" };
    if (body !== undefined && !isForm) headers["Content-Type"] = "application/json";
    const r = await fetch(url, {
      method, headers, credentials: "same-origin",
      body: body === undefined ? undefined : isForm ? body : JSON.stringify(body),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Request failed (" + r.status + ")");
    return data;
  }

  let market = null;
  async function marketInfo() {
    if (!market) {
      const m = await api("GET", "/api/market-key");
      market = { key: b64d(m.key), serverPk: b64d(m.server_signing_pubkey) };
    }
    return market;
  }
  const sealJson = async (obj) => seal(utf8(canonical(obj)), (await marketInfo()).key);
  const openJson = async (blob) => JSON.parse(dec.decode(open(blob, (await marketInfo()).key)));

  // "user" | "server" | null. Same semantics as crypto.sig_origin() on the server.
  async function sigOrigin(ctx, data, sig, userPk) {
    if (verify(ctx, data, sig, userPk)) return "user";
    if (verify(ctx, data, sig, (await marketInfo()).serverPk)) return "server";
    return null;
  }

  // --- Session key storage -------------------------------------------------------------

  const body = () => document.body.dataset;
  const seedKey = () => "d1zzy.seed." + body().userId;

  function storeIdentity(ident) {
    try { sessionStorage.setItem(seedKey(), S.to_hex(ident.seed)); } catch (e) { /* private mode */ }
  }
  function loadIdentity() {
    try {
      const hex = sessionStorage.getItem(seedKey());
      return hex ? identityFromSeed(S.from_hex(hex)) : null;
    } catch (e) {
      return null;
    }
  }
  function forget() {
    try { sessionStorage.removeItem(seedKey()); } catch (e) { /* ignore */ }
  }
  // The server's copy of my public key, rendered into <body data-signing-pubkey>.
  function matchesAccount(ident) {
    const pk = body().signingPubkey;
    return !!pk && b64e(ident.signingPk) === pk;
  }

  // Encrypted per-user local store (ratchet sessions, decrypted message cache).
  function localKey(ident) {
    return S.crypto_generichash(32, utf8("local-store"), ident.seed);
  }
  function localGet(ident, name) {
    try {
      const raw = localStorage.getItem("d1zzy." + body().userId + "." + name);
      return raw ? JSON.parse(dec.decode(open(b64d(raw), localKey(ident), utf8(name)))) : null;
    } catch (e) {
      return null;
    }
  }
  function localSet(ident, name, value) {
    try {
      const blob = seal(utf8(JSON.stringify(value)), localKey(ident), utf8(name));
      localStorage.setItem("d1zzy." + body().userId + "." + name, b64e(blob));
    } catch (e) { /* quota or private mode: sessions just won't persist */ }
  }

  self.D1 = {
    ready, CONTEXTS, b64e, b64d, utf8, dec, concat, canonical, seal, open, sign, verify,
    salt, identityFromSeed, deriveIdentity, api, marketInfo, sealJson, openJson, sigOrigin,
    storeIdentity, loadIdentity, forget, matchesAccount, localGet, localSet,
    get sodium() { return S; },
  };
})();
