"""Server-side crypto. Mirrors app/static/js/crypto.js byte for byte.

Primitives (libsodium via PyNaCl):
  * Ed25519 signatures with a domain-separation prefix per object type.
  * X25519 key agreement (keys derived from the Ed25519 identity key).
  * XChaCha20-Poly1305 AEAD for blobs. The spec asked for AES-GCM, but libsodium's
    WASM build has no AES-GCM (it needs AES-NI), so both sides use XChaCha20-Poly1305.

Blob format: 24-byte random nonce || ciphertext+tag.
"""

import base64
import json
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import nacl.bindings as b
import nacl.encoding
import nacl.exceptions
import nacl.hash
import nacl.pwhash
import nacl.signing

from app.config import get_settings

NONCE_BYTES = b.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # 24
KEY_BYTES = 32

CONTEXTS = {
    "listing": b"d1zzy:listing:v1\x00",
    "offer": b"d1zzy:offer:v1\x00",
    "rating": b"d1zzy:rating:v1\x00",
    "report": b"d1zzy:report:v1\x00",
    "keys": b"d1zzy:keys:v1\x00",
}


class CryptoError(ValueError):
    pass


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(data: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except (ValueError, TypeError) as e:
        raise CryptoError("invalid base64") from e


def _derived_key(name: str, configured: str) -> bytes:
    if configured:
        key = b64d(configured)
        if len(key) != KEY_BYTES:
            raise CryptoError(f"{name} must be 32 bytes, base64 encoded")
        return key
    # Development fallback only: derive from SECRET_KEY so a fresh checkout works.
    return nacl.hash.blake2b(
        get_settings().secret_key.encode(),
        digest_size=KEY_BYTES,
        person=name.encode()[:16].ljust(16, b"\0"),
        encoder=nacl.encoding.RawEncoder,
    )


@lru_cache
def market_key() -> bytes:
    return _derived_key("market_key", get_settings().market_key)


@lru_cache
def server_signing_key() -> nacl.signing.SigningKey:
    return nacl.signing.SigningKey(_derived_key("server_sign", get_settings().server_signing_seed))


def server_verify_key() -> bytes:
    return bytes(server_signing_key().verify_key)


# --- AEAD -------------------------------------------------------------------------------


def seal(plaintext: bytes, key: bytes, ad: bytes = b"") -> bytes:
    nonce = os.urandom(NONCE_BYTES)
    return nonce + b.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad or None, nonce, key)


def open_sealed(blob: bytes, key: bytes, ad: bytes = b"") -> bytes:
    if len(blob) < NONCE_BYTES + 16:
        raise CryptoError("ciphertext too short")
    try:
        return b.crypto_aead_xchacha20poly1305_ietf_decrypt(
            blob[NONCE_BYTES:], ad or None, blob[:NONCE_BYTES], key
        )
    except nacl.exceptions.CryptoError as e:
        raise CryptoError("decryption failed") from e


def seal_json(obj: Any, key: bytes | None = None) -> bytes:
    data = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    return seal(data, key or market_key())


def open_json(blob: bytes, key: bytes | None = None) -> Any:
    try:
        return json.loads(open_sealed(blob, key or market_key()))
    except json.JSONDecodeError as e:
        raise CryptoError("plaintext is not JSON") from e


# --- Signatures -------------------------------------------------------------------------


def signed_message(context: str, data: bytes) -> bytes:
    return CONTEXTS[context] + data


def verify(pubkey: bytes | None, context: str, data: bytes, sig: bytes) -> bool:
    if not pubkey or len(pubkey) != 32 or len(sig) != 64:
        return False
    try:
        nacl.signing.VerifyKey(pubkey).verify(signed_message(context, data), sig)
        return True
    except nacl.exceptions.BadSignatureError:
        return False


def server_sign(context: str, data: bytes) -> bytes:
    return server_signing_key().sign(signed_message(context, data)).signature


def sig_origin(context: str, data: bytes, sig: bytes, user_pubkey: bytes | None) -> str | None:
    """'user' if signed by the author's own key, 'server' if signed on their behalf by the
    no-JS fallback, None if the signature is invalid (tampered data)."""
    if verify(user_pubkey, context, data, sig):
        return "user"
    if verify(server_verify_key(), context, data, sig):
        return "server"
    return None


def report_payload(target_type: str, target_id: str, reason: str, details_ct: bytes) -> bytes:
    return b"\x00".join([target_type.encode(), target_id.encode(), reason.encode(), details_ct])


def keys_payload(user_id: str, signing_pk: bytes, exchange_pk: bytes, profile_pk: bytes) -> bytes:
    return user_id.encode() + signing_pk + exchange_pk + profile_pk


# --- Key exchange -----------------------------------------------------------------------


def x25519(sk: bytes, pk: bytes) -> bytes:
    return b.crypto_scalarmult(sk, pk)


def ed25519_pk_to_x25519(pk: bytes) -> bytes:
    return b.crypto_sign_ed25519_pk_to_curve25519(pk)


# --- Passphrase -> identity (same derivation as the browser) ----------------------------


@dataclass(frozen=True)
class Identity:
    seed: bytes
    signing_sk: bytes  # 64-byte libsodium secret key
    signing_pk: bytes
    exchange_sk: bytes
    exchange_pk: bytes
    profile_sk: bytes
    profile_pk: bytes

    def sign(self, context: str, data: bytes) -> bytes:
        return nacl.signing.SigningKey(self.seed).sign(signed_message(context, data)).signature


def passphrase_salt(email: str) -> bytes:
    return nacl.hash.blake2b(
        b"d1zzy-salt:" + email.strip().lower().encode(),
        digest_size=16,
        encoder=nacl.encoding.RawEncoder,
    )


def identity_from_seed(seed: bytes) -> Identity:
    pk, sk = b.crypto_sign_seed_keypair(seed)
    xsk = b.crypto_sign_ed25519_sk_to_curve25519(sk)
    psk = nacl.hash.blake2b(b"profile", key=seed, digest_size=32, encoder=nacl.encoding.RawEncoder)
    return Identity(
        seed=seed,
        signing_sk=sk,
        signing_pk=pk,
        exchange_sk=xsk,
        exchange_pk=b.crypto_scalarmult_base(xsk),
        profile_sk=psk,
        profile_pk=b.crypto_scalarmult_base(psk),
    )


def identity_from_passphrase(email: str, passphrase: str) -> Identity:
    seed = nacl.pwhash.argon2id.kdf(
        32,
        passphrase.encode(),
        passphrase_salt(email),
        opslimit=nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE,
        memlimit=nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE,
    )
    return identity_from_seed(seed)


def safety_number(
    conversation_id: str,
    participants: list[tuple[str, bytes | None, bytes | None]],
) -> str:
    """A 60-digit fingerprint of both identities in a conversation.

    Both sides compute the same digits from the same public keys, so users can read the
    number to each other over another channel. If a server swaps a peer key, the numbers
    will not match.
    """
    rows = []
    for user_id, signing_pk, exchange_pk in participants:
        rows.append(
            str(user_id).encode() + b"\x00" + (signing_pk or b"") + b"\x00" + (exchange_pk or b"")
        )
    rows.sort()
    digest = nacl.hash.blake2b(
        b"d1zzy-safety:v1\x00" + str(conversation_id).encode() + b"\x00" + b"\x00".join(rows),
        digest_size=32,
        encoder=nacl.encoding.RawEncoder,
    )
    number = int.from_bytes(digest, "big") % (10**60)
    digits = f"{number:060d}"
    return " ".join(digits[i : i + 5] for i in range(0, 60, 5))
