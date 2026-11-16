// Runs the real browser crypto (vendored libsodium + app/static/js/*.js) under Node so the
// Python test-suite can check byte-for-byte compatibility. Reads one JSON job on stdin.
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const root = path.resolve(__dirname, "../../app/static");
const store = () => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }; };
const ctx = {
  console, WebAssembly, TextEncoder, TextDecoder, crypto: globalThis.crypto || require("crypto").webcrypto, setTimeout, clearTimeout,
  Uint8Array, atob, btoa, performance, fetch: undefined,
  sessionStorage: store(), localStorage: store(),
  document: { body: { dataset: { userId: "test" } }, querySelector: () => null },
};
ctx.self = ctx; ctx.window = ctx;
vm.createContext(ctx);
for (const f of ["vendor/libsodium.wasm.js", "js/crypto.js", "js/ratchet.js"]) {
  vm.runInContext(fs.readFileSync(path.join(root, f), "utf8"), ctx, { filename: f });
}

const job = JSON.parse(fs.readFileSync(0, "utf8"));
ctx.D1.ready.then(() => {
  const D = ctx.D1, R = ctx.D1Ratchet, b = D.b64d, e = D.b64e;
  const out = {};
  if (job.identity) {
    const id = D.deriveIdentity(job.identity.email, job.identity.passphrase);
    out.identity = { seed: e(id.seed), signing_pk: e(id.signingPk), exchange_pk: e(id.exchangePk), profile_pk: e(id.profilePk) };
  }
  if (job.open) {
    const pt = D.open(b(job.open.blob), b(job.open.key));
    out.opened = JSON.parse(D.dec.decode(pt));
    out.verified = D.verify(job.open.context, b(job.open.blob), b(job.open.sig), b(job.open.pk));
  }
  if (job.seal) {
    const id = D.identityFromSeed(b(job.seal.seed));
    const blob = D.seal(D.utf8(D.canonical(job.seal.obj)), b(job.seal.key));
    out.sealed = { blob: e(blob), sig: e(D.sign(job.seal.context, blob, id.signingSk)) };
  }
  if (job.ratchet) {
    const r = job.ratchet, id = D.identityFromSeed(b(r.seed));
    let st = R.init({ convId: r.conv, isAlice: r.is_alice, myExchangeSk: id.exchangeSk, myExchangePk: id.exchangePk, theirExchangePk: b(r.their_pk) });
    out.received = [];
    for (const m of r.incoming) {
      let pt; [st, pt] = R.decrypt(st, b(m.header), b(m.ct));
      out.received.push(D.dec.decode(pt));
    }
    out.replies = [];
    for (const text of r.send) {
      let hb, ct; [st, hb, ct] = R.encrypt(st, D.utf8(text));
      out.replies.push({ header: e(hb), ct: e(ct) });
    }
  }
  process.stdout.write(JSON.stringify(out));
}).catch((err) => { process.stderr.write(String(err && err.stack || err)); process.exit(1); });
