/* Double Ratchet. JS twin of app/core/ratchet.py (read that file's docstring for the
 * protocol). State objects are plain JSON with base64 fields and are interchangeable with
 * the Python implementation. Functions return a new state; inputs are never mutated, so a
 * failed decrypt leaves the session intact. */
(function () {
  "use strict";
  const MAX_SKIP = 1000;
  const D = () => self.D1;
  const S = () => self.D1.sodium;

  const h = (data, key, size) => S().crypto_generichash(size || 32, data, key);
  const kdfRk = (rk, dhOut) => {
    const out = h(D().concat(D().utf8("rk"), dhOut), rk, 64);
    return [out.subarray(0, 32), out.subarray(32)];
  };
  const kdfCk = (ck) => [h(new Uint8Array([2]), ck), h(new Uint8Array([1]), ck)];
  const dh = (sk, pk) => S().crypto_scalarmult(sk, pk);
  const keypair = () => {
    const sk = S().randombytes_buf(32);
    return [sk, S().crypto_scalarmult_base(sk)];
  };
  const ad = (conv, header) => D().concat(D().utf8("d1zzy-dr:" + conv), header);
  const clone = (st) => JSON.parse(JSON.stringify(st));

  function sharedSecret(mySk, theirPk, conv) {
    const key = D().utf8("d1zzy-dr-v1:" + conv).subarray(0, 64);
    return h(dh(mySk, theirPk), key);
  }

  function init({ convId, isAlice, myExchangeSk, myExchangePk, theirExchangePk }) {
    const e = D().b64e, sk = sharedSecret(myExchangeSk, theirExchangePk, convId);
    const st = {
      conv: convId, PN: 0, Ns: 0, Nr: 0, skipped: {}, CKr: null, init_n: 0, alice: isAlice,
      CKinit: e(h(D().utf8("init"), sk)),
    };
    if (isAlice) {
      const [dsk, dpk] = keypair();
      const [rk, cks] = kdfRk(sk, dh(dsk, theirExchangePk));
      Object.assign(st, { DHs: [e(dsk), e(dpk)], DHr: e(theirExchangePk), RK: e(rk), CKs: e(cks) });
    } else {
      Object.assign(st, { DHs: [e(myExchangeSk), e(myExchangePk)], DHr: null, RK: e(sk), CKs: null });
    }
    return st;
  }

  function encrypt(state, plaintext) {
    const st = clone(state), e = D().b64e, d = D().b64d;
    let header, mk, ck;
    if (st.CKs === null) {
      [ck, mk] = kdfCk(d(st.CKinit));
      st.CKinit = e(ck);
      header = { i: 1, n: st.init_n++ };
    } else {
      [ck, mk] = kdfCk(d(st.CKs));
      st.CKs = e(ck);
      header = { dh: st.DHs[1], pn: st.PN, n: st.Ns++ };
    }
    const hb = D().utf8(JSON.stringify(header));
    return [st, hb, D().seal(plaintext, mk, ad(st.conv, hb))];
  }

  function skip(st, chain, until, tag, counter) {
    if (st[chain] === null || st[chain] === undefined) return;
    if (until - st[counter] > MAX_SKIP) throw new Error("too many skipped messages");
    let ck = D().b64d(st[chain]), mk;
    while (st[counter] < until) {
      [ck, mk] = kdfCk(ck);
      st.skipped[tag + ":" + st[counter]] = D().b64e(mk);
      st[counter] += 1;
    }
    st[chain] = D().b64e(ck);
  }

  function decrypt(state, header, ciphertext) {
    const st = clone(state), e = D().b64e, d = D().b64d;
    const hdr = JSON.parse(D().dec.decode(header));
    const n = hdr.n | 0, a = ad(st.conv, header);
    let ck, mk;

    if (hdr.i) {
      const key = "init:" + n;
      if (key in st.skipped) {
        mk = d(st.skipped[key]);
        delete st.skipped[key];
        return [st, D().open(ciphertext, mk, a)];
      }
      if (!st.alice) throw new Error("unexpected init-chain message");
      skip(st, "CKinit", n, "init", "init_n");
      [ck, mk] = kdfCk(d(st.CKinit));
      st.CKinit = e(ck);
      st.init_n += 1;
      return [st, D().open(ciphertext, mk, a)];
    }

    const key = hdr.dh + ":" + n;
    if (key in st.skipped) {
      mk = d(st.skipped[key]);
      delete st.skipped[key];
      return [st, D().open(ciphertext, mk, a)];
    }
    if (hdr.dh !== st.DHr) {
      skip(st, "CKr", hdr.pn | 0, String(st.DHr), "Nr");
      st.PN = st.Ns; st.Ns = 0; st.Nr = 0;
      st.DHr = hdr.dh;
      let [rk, ckr] = kdfRk(d(st.RK), dh(d(st.DHs[0]), d(hdr.dh)));
      const [nsk, npk] = keypair();
      let cks;
      [rk, cks] = kdfRk(rk, dh(nsk, d(hdr.dh)));
      Object.assign(st, { RK: e(rk), CKr: e(ckr), CKs: e(cks), DHs: [e(nsk), e(npk)] });
    }
    skip(st, "CKr", n, hdr.dh, "Nr");
    [ck, mk] = kdfCk(d(st.CKr));
    st.CKr = e(ck);
    st.Nr += 1;
    return [st, D().open(ciphertext, mk, a)];
  }

  self.D1Ratchet = { init, encrypt, decrypt, sharedSecret };
})();
