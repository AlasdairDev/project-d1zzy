"""Double Ratchet (Signal spec, rev. 4). Python twin of app/static/js/ratchet.js.

The server never runs this for real conversations; it only relays opaque header/ciphertext
pairs. This module exists so tests and the CLI can speak the same protocol as browsers.

Bootstrap ("X3DH-lite"): there is no prekey server, so the shared secret comes from the two
parties' static X25519 identity keys, bound to the conversation id:

    SK = BLAKE2b-256(key = "d1zzy-dr-v1:" || conv_id, msg = DH(IK_a, IK_b))

Roles are fixed: participant1 (lower id) is Alice and ratchets immediately with a fresh key;
participant2 is Bob and starts with his identity key as ratchet key, as in Signal. Bob may
send before he has heard from Alice using a one-way "init chain" derived from SK; it is
abandoned after his first DH ratchet step. Forward secrecy begins at the first DH step.

Header: JSON {"dh": b64, "pn": int, "n": int} or {"i": 1, "n": int} for the init chain.
Message: XChaCha20-Poly1305 under the message key, AD = "d1zzy-dr:" || conv_id || header.
"""

import copy
import json
import os
from typing import Any

import nacl.bindings as b
import nacl.encoding
import nacl.hash

from app.core.crypto import CryptoError, b64d, b64e, open_sealed, seal

MAX_SKIP = 1000

State = dict[str, Any]


def _h(data: bytes, key: bytes, size: int = 32) -> bytes:
    return nacl.hash.blake2b(data, key=key, digest_size=size, encoder=nacl.encoding.RawEncoder)


def _kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    out = _h(b"rk" + dh_out, rk, 64)
    return out[:32], out[32:]


def _kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    return _h(b"\x02", ck), _h(b"\x01", ck)  # (next chain key, message key)


def _keypair() -> tuple[bytes, bytes]:
    sk = os.urandom(32)
    return sk, b.crypto_scalarmult_base(sk)


def _ad(conv_id: str, header: bytes) -> bytes:
    return b"d1zzy-dr:" + conv_id.encode() + header


def shared_secret(my_exchange_sk: bytes, their_exchange_pk: bytes, conv_id: str) -> bytes:
    dh = b.crypto_scalarmult(my_exchange_sk, their_exchange_pk)
    return _h(dh, (b"d1zzy-dr-v1:" + conv_id.encode())[:64])


def init(
    *,
    conv_id: str,
    is_alice: bool,
    my_exchange_sk: bytes,
    my_exchange_pk: bytes,
    their_exchange_pk: bytes,
) -> State:
    sk = shared_secret(my_exchange_sk, their_exchange_pk, conv_id)
    ck_init = _h(b"init", sk)
    st: State = {
        "conv": conv_id,
        "PN": 0,
        "Ns": 0,
        "Nr": 0,
        "skipped": {},
        "CKr": None,
        "init_n": 0,
        "alice": is_alice,
    }
    if is_alice:
        dhs_sk, dhs_pk = _keypair()
        rk, cks = _kdf_rk(sk, b.crypto_scalarmult(dhs_sk, their_exchange_pk))
        st |= {
            "DHs": [b64e(dhs_sk), b64e(dhs_pk)],
            "DHr": b64e(their_exchange_pk),
            "RK": b64e(rk),
            "CKs": b64e(cks),
            "CKinit": b64e(ck_init),  # receives Bob's init chain
        }
    else:
        st |= {
            "DHs": [b64e(my_exchange_sk), b64e(my_exchange_pk)],
            "DHr": None,
            "RK": b64e(sk),
            "CKs": None,
            "CKinit": b64e(ck_init),  # sends on the init chain until the first DH step
        }
    return st


def encrypt(state: State, plaintext: bytes) -> tuple[State, bytes, bytes]:
    st = copy.deepcopy(state)
    if st["CKs"] is None:
        ck, mk = _kdf_ck(b64d(st["CKinit"]))
        st["CKinit"] = b64e(ck)
        header = {"i": 1, "n": st["init_n"]}
        st["init_n"] += 1
    else:
        ck, mk = _kdf_ck(b64d(st["CKs"]))
        st["CKs"] = b64e(ck)
        header = {"dh": st["DHs"][1], "pn": st["PN"], "n": st["Ns"]}
        st["Ns"] += 1
    hb = json.dumps(header, separators=(",", ":")).encode()
    return st, hb, seal(plaintext, mk, _ad(st["conv"], hb))


def _skip(st: State, chain: str, until: int, tag: str, counter: str) -> None:
    if st[chain] is None:
        return
    if until - st[counter] > MAX_SKIP:
        raise CryptoError("too many skipped messages")
    ck = b64d(st[chain])
    while st[counter] < until:
        ck, mk = _kdf_ck(ck)
        st["skipped"][f"{tag}:{st[counter]}"] = b64e(mk)
        st[counter] += 1
    st[chain] = b64e(ck)


def decrypt(state: State, header: bytes, ciphertext: bytes) -> tuple[State, bytes]:
    """Returns (new_state, plaintext). The input state is never mutated, so a failed
    decryption (tampering, wrong conversation) leaves the session usable."""
    st = copy.deepcopy(state)
    try:
        h = json.loads(header)
        n = int(h["n"])
    except (ValueError, KeyError, TypeError) as e:
        raise CryptoError("malformed header") from e
    ad = _ad(st["conv"], header)

    if h.get("i"):
        key = f"init:{n}"
        if key not in st["skipped"]:
            if not st["alice"]:
                raise CryptoError("unexpected init-chain message")
            _skip(st, "CKinit", n, "init", "init_n")
            ck, mk = _kdf_ck(b64d(st["CKinit"]))
            st["CKinit"] = b64e(ck)
            st["init_n"] += 1
            return st, open_sealed(ciphertext, mk, ad)
        return st, open_sealed(ciphertext, b64d(st["skipped"].pop(key)), ad)

    dh = h["dh"]
    key = f"{dh}:{n}"
    if key in st["skipped"]:
        return st, open_sealed(ciphertext, b64d(st["skipped"].pop(key)), ad)

    if dh != st["DHr"]:
        _skip(st, "CKr", int(h["pn"]), str(st["DHr"]), "Nr")
        # DH ratchet step
        st["PN"], st["Ns"], st["Nr"] = st["Ns"], 0, 0
        st["DHr"] = dh
        dhs_sk = b64d(st["DHs"][0])
        rk, ckr = _kdf_rk(b64d(st["RK"]), b.crypto_scalarmult(dhs_sk, b64d(dh)))
        new_sk, new_pk = _keypair()
        rk, cks = _kdf_rk(rk, b.crypto_scalarmult(new_sk, b64d(dh)))
        st |= {
            "RK": b64e(rk),
            "CKr": b64e(ckr),
            "CKs": b64e(cks),
            "DHs": [b64e(new_sk), b64e(new_pk)],
        }

    _skip(st, "CKr", n, dh, "Nr")
    ck, mk = _kdf_ck(b64d(st["CKr"]))
    st["CKr"] = b64e(ck)
    st["Nr"] += 1
    return st, open_sealed(ciphertext, mk, ad)
