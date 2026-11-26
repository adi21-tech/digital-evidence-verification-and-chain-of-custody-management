"""Minimal server-side WebAuthn verification (Windows Hello / fingerprint / passkeys).

Supports "none" attestation and ES256 / RS256 credentials, which is what Windows Hello,
Touch ID and Android fingerprint sensors produce. Only depends on `cryptography`.
"""
import base64
import hashlib
import json
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


def b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- tiny CBOR decoder
def cbor_decode(data: bytes, i: int = 0):
    """Decode one CBOR item starting at offset i. Returns (value, next_offset)."""
    ib = data[i]
    i += 1
    major, ai = ib >> 5, ib & 0x1F
    if ai < 24:
        val = ai
    elif ai == 24:
        val = data[i]
        i += 1
    elif ai == 25:
        val = struct.unpack(">H", data[i:i + 2])[0]
        i += 2
    elif ai == 26:
        val = struct.unpack(">I", data[i:i + 4])[0]
        i += 4
    elif ai == 27:
        val = struct.unpack(">Q", data[i:i + 8])[0]
        i += 8
    else:
        raise ValueError("unsupported CBOR length encoding")
    if major == 0:
        return val, i
    if major == 1:
        return -1 - val, i
    if major == 2:
        return bytes(data[i:i + val]), i + val
    if major == 3:
        return data[i:i + val].decode(), i + val
    if major == 4:
        out = []
        for _ in range(val):
            v, i = cbor_decode(data, i)
            out.append(v)
        return out, i
    if major == 5:
        out = {}
        for _ in range(val):
            k, i = cbor_decode(data, i)
            v, i = cbor_decode(data, i)
            out[k] = v
        return out, i
    if major == 7 and ai in (20, 21, 22):
        return {20: False, 21: True, 22: None}[ai], i
    raise ValueError("unsupported CBOR type")


# ---------------------------------------------------------------- WebAuthn parsing
def parse_auth_data(ad: bytes) -> dict:
    out = {
        "rp_id_hash": ad[:32],
        "flags": ad[32],
        "sign_count": struct.unpack(">I", ad[33:37])[0],
    }
    out["up"] = bool(out["flags"] & 0x01)   # user present
    out["uv"] = bool(out["flags"] & 0x04)   # user verified (fingerprint / PIN)
    out["at"] = bool(out["flags"] & 0x40)   # attested credential data included
    if out["at"]:
        cred_len = struct.unpack(">H", ad[53:55])[0]
        out["cred_id"] = ad[55:55 + cred_len]
        key, end = cbor_decode(ad, 55 + cred_len)
        out["cose_key"] = key
        out["cose_raw"] = ad[55 + cred_len:end]
    return out


def _check_client_data(cd_b64: str, expected_type: str, challenge: str, origin: str) -> bytes:
    raw = b64u_dec(cd_b64)
    cd = json.loads(raw)
    if cd.get("type") != expected_type:
        raise ValueError("wrong clientData type")
    if cd.get("challenge") != challenge:
        raise ValueError("challenge mismatch")
    if cd.get("origin") != origin:
        raise ValueError(f"origin mismatch ({cd.get('origin')} != {origin})")
    return raw


def _public_key(cose: dict):
    kty = cose.get(1)
    if kty == 2 and cose.get(3) == -7:  # EC2 / ES256 (P-256)
        x = int.from_bytes(cose[-2], "big")
        y = int.from_bytes(cose[-3], "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    if kty == 3:                         # RSA / RS256
        n = int.from_bytes(cose[-1], "big")
        e = int.from_bytes(cose[-2], "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    raise ValueError("unsupported credential key type")


def verify_registration(body: dict, challenge: str, rp_id: str, origin: str) -> dict:
    resp = body["response"]
    _check_client_data(resp["clientDataJSON"], "webauthn.create", challenge, origin)
    att, _ = cbor_decode(b64u_dec(resp["attestationObject"]))
    p = parse_auth_data(att["authData"])
    if p["rp_id_hash"] != hashlib.sha256(rp_id.encode()).digest():
        raise ValueError("rpId hash mismatch")
    if not (p["up"] and p["uv"] and p["at"]):
        raise ValueError("fingerprint / user verification was not performed")
    _public_key(p["cose_key"])  # make sure we can use it later
    if body.get("id") and body["id"] != b64u_enc(p["cred_id"]):
        raise ValueError("credential id mismatch")
    return {"cred_id": b64u_enc(p["cred_id"]), "cose_raw": p["cose_raw"], "sign_count": p["sign_count"]}


def verify_assertion(body: dict, challenge: str, rp_id: str, origin: str,
                     cose_raw: bytes, stored_sign_count: int) -> int:
    resp = body["response"]
    cd_raw = _check_client_data(resp["clientDataJSON"], "webauthn.get", challenge, origin)
    auth_data = b64u_dec(resp["authenticatorData"])
    p = parse_auth_data(auth_data)
    if p["rp_id_hash"] != hashlib.sha256(rp_id.encode()).digest():
        raise ValueError("rpId hash mismatch")
    if not (p["up"] and p["uv"]):
        raise ValueError("fingerprint / user verification was not performed")
    signed = auth_data + hashlib.sha256(cd_raw).digest()
    sig = b64u_dec(resp["signature"])
    cose, _ = cbor_decode(cose_raw)
    pub = _public_key(cose)
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
        else:
            pub.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise ValueError("invalid fingerprint signature")
    # Many platform authenticators always return 0; only enforce when a counter is in use.
    if (p["sign_count"] or stored_sign_count) and p["sign_count"] <= stored_sign_count:
        raise ValueError("signature counter did not increase (possible cloned authenticator)")
    return p["sign_count"]
