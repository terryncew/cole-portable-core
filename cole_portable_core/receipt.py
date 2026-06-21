"""Issue and verify separately signed COLE derived measurement receipts."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canon import validate_disclosure
from .canonical import CANONICALIZATION_ID, sign_object, verify_signed_object
from .core import ALGORITHM_ID, evaluate, reference_profile, validate_profile


SPEC_URI = "https://github.com/terryncew/cole-portable-core"
HASH256 = re.compile(r"^[0-9a-f]{64}$")
BODY_FIELDS = {
    "kind", "receipt_version", "algorithm_id", "canonicalization_id", "spec_uri",
    "attestation", "input_receipt_hash", "input_trace_id", "previous_input_receipt_hash",
    "profile", "measurement",
}


def _inputs(receipt: Mapping[str, Any], disclosure: Mapping[str, Any]) -> tuple[dict, list[int]]:
    validate_disclosure(disclosure, receipt)
    return disclosure["semantic_graph"], [item["value_micros"] for item in disclosure["signals"]]


def issue_measurement_receipt(
    input_receipt: Mapping[str, Any],
    disclosure: Mapping[str, Any],
    key: Ed25519PrivateKey,
    *,
    previous_input_receipt: Mapping[str, Any] | None = None,
    previous_disclosure: Mapping[str, Any] | None = None,
    profile: dict | None = None,
) -> dict:
    graph, signal = _inputs(input_receipt, disclosure)
    if (previous_input_receipt is None) != (previous_disclosure is None):
        raise ValueError("previous receipt and disclosure must be supplied together")
    previous_graph = None
    previous_hash = None
    if previous_input_receipt is not None and previous_disclosure is not None:
        previous_graph, _ = _inputs(previous_input_receipt, previous_disclosure)
        previous_hash = previous_input_receipt["payload_hash"]
    selected = dict(reference_profile(input_receipt["signal_schema_id"]) if profile is None else profile)
    validate_profile(selected)
    if selected["signal_schema_id"] != input_receipt["signal_schema_id"]:
        raise ValueError("profile signal schema does not match Canon input")
    measurement = evaluate(graph, signal, previous_graph, selected).as_dict()
    body = {
        "kind": "cole_measurement_receipt",
        "receipt_version": "0.1-draft",
        "algorithm_id": ALGORITHM_ID,
        "canonicalization_id": CANONICALIZATION_ID,
        "spec_uri": SPEC_URI,
        "attestation": "self",
        "input_receipt_hash": input_receipt["payload_hash"],
        "input_trace_id": input_receipt["trace_id"],
        "previous_input_receipt_hash": previous_hash,
        "profile": selected,
        "measurement": measurement,
    }
    return sign_object(body, key)


def validate_measurement_profile(receipt: Mapping[str, Any]) -> None:
    if not isinstance(receipt, Mapping) or set(receipt) != BODY_FIELDS | {"payload_hash", "signature"}:
        raise ValueError("derived receipt field mismatch")
    if receipt["kind"] != "cole_measurement_receipt" or receipt["receipt_version"] != "0.1-draft":
        raise ValueError("unsupported derived receipt profile")
    if receipt["algorithm_id"] != ALGORITHM_ID or receipt["canonicalization_id"] != CANONICALIZATION_ID:
        raise ValueError("unsupported derived algorithm")
    if receipt["spec_uri"] != SPEC_URI or receipt["attestation"] != "self":
        raise ValueError("unsupported derived trust profile")
    for field in ("input_receipt_hash", "payload_hash"):
        if not isinstance(receipt[field], str) or not HASH256.fullmatch(receipt[field]):
            raise ValueError(f"invalid {field}")
    previous = receipt["previous_input_receipt_hash"]
    if previous is not None and (not isinstance(previous, str) or not HASH256.fullmatch(previous)):
        raise ValueError("invalid previous input hash")
    validate_profile(receipt["profile"])


def verify_measurement_receipt(
    derived_receipt: Mapping[str, Any],
    input_receipt: Mapping[str, Any],
    disclosure: Mapping[str, Any],
    *,
    previous_input_receipt: Mapping[str, Any] | None = None,
    previous_disclosure: Mapping[str, Any] | None = None,
    expected_public_key: str | None = None,
) -> bool:
    try:
        validate_measurement_profile(derived_receipt)
        if not verify_signed_object(derived_receipt):
            return False
        if expected_public_key is not None and derived_receipt["signature"]["public_key"] != expected_public_key:
            return False
        graph, signal = _inputs(input_receipt, disclosure)
        if derived_receipt["input_receipt_hash"] != input_receipt["payload_hash"] or derived_receipt["input_trace_id"] != input_receipt["trace_id"]:
            return False
        if (previous_input_receipt is None) != (previous_disclosure is None):
            return False
        previous_graph = None
        previous_hash = None
        if previous_input_receipt is not None and previous_disclosure is not None:
            previous_graph, _ = _inputs(previous_input_receipt, previous_disclosure)
            previous_hash = previous_input_receipt["payload_hash"]
        if derived_receipt["previous_input_receipt_hash"] != previous_hash:
            return False
        profile = derived_receipt["profile"]
        if profile["signal_schema_id"] != input_receipt["signal_schema_id"]:
            return False
        return evaluate(graph, signal, previous_graph, profile).as_dict() == derived_receipt["measurement"]
    except (KeyError, TypeError, ValueError):
        return False
