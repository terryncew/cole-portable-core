"""Strict integer-only canonical JSON and signed-envelope helpers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


MAX_SAFE_INTEGER = (1 << 53) - 1
CANONICALIZATION_ID = "olp-canonical-json-int-v1"


def validate_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if isinstance(value, bool) or abs(value) > MAX_SAFE_INTEGER:
            raise ValueError(f"{path}: integer outside interoperable range")
        return
    if isinstance(value, float):
        raise ValueError(f"{path}: floats are forbidden")
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            validate_value(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ValueError(f"{path}: keys must be ASCII strings")
            validate_value(item, f"{path}.{key}")
        return
    raise ValueError(f"{path}: unsupported value type {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    validate_value(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def sha256_canonical(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def parse_json_strict(text: str) -> Any:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate object key: {key}")
            result[key] = value
        return result

    value = json.loads(
        text,
        object_pairs_hook=reject_duplicate,
        parse_float=lambda _: (_ for _ in ()).throw(ValueError("floats are forbidden")),
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite values are forbidden")),
    )
    validate_value(value)
    return value


def sign_object(body: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    if "payload_hash" in body or "signature" in body:
        raise ValueError("body must not contain envelope fields")
    payload = canonical_json(body)
    return {
        **body,
        "payload_hash": hashlib.sha256(payload).hexdigest(),
        "signature": {
            "algorithm": "Ed25519",
            "public_key": key.public_key().public_bytes_raw().hex(),
            "value": key.sign(payload).hex(),
        },
    }


def verify_signed_object(value: Mapping[str, Any]) -> bool:
    try:
        body = dict(value)
        signature = body.pop("signature")
        payload_hash = body.pop("payload_hash")
        if set(signature) != {"algorithm", "public_key", "value"}:
            return False
        if signature["algorithm"] != "Ed25519":
            return False
        payload = canonical_json(body)
        if hashlib.sha256(payload).hexdigest() != payload_hash:
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signature["public_key"])).verify(
            bytes.fromhex(signature["value"]), payload
        )
        return len(signature["public_key"]) == 64 and len(signature["value"]) == 128
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False
