"""Generate deterministic Python-signed conformance vectors."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cole_portable_core.canonical import sha256_canonical, sign_object
from cole_portable_core.core import conformance_profile
from cole_portable_core.receipt import issue_measurement_receipt


VECTORS = ROOT / "vectors"
INPUT_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32))
MEASUREMENT_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("22" * 32))
SCHEMA = "test.normalized-signal.v1"


def h(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def graph(changed: bool = False, empty: bool = False) -> dict:
    if empty:
        return {"claims": [], "evidence": [], "relations": []}
    return {
        "claims": [{"id": "claim_1", "content_hash": h("claim changed" if changed else "claim"), "material": True}],
        "evidence": [{"id": "evidence_1", "content_hash": h("evidence"), "observed": True}],
        "relations": [{"src": "evidence_1", "dst": "claim_1", "relation_type": "supports"}],
    }


def claim_window(start: int, count: int) -> dict:
    return {
        "claims": [
            {"id": f"claim_{index:02d}", "content_hash": h(f"claim:{index:02d}"), "material": False}
            for index in range(start, start + count)
        ],
        "evidence": [],
        "relations": [],
    }


def make_input(semantic_graph: dict, signals: list[int], trace_id: str) -> tuple[dict, dict]:
    schema = SCHEMA if signals else None
    body = {
        "kind": "coherence_input_receipt",
        "receipt_version": "0.1",
        "algorithm_id": "cole-conformance-input-0.1",
        "canonicalization_id": "olp-canonical-json-int-v1",
        "spec_uri": "https://github.com/terryncew/olp-wire-canon",
        "attestation": "self",
        "capture_status": "provisional",
        "trace_id": trace_id,
        "capture_loss": False,
        "dropped_span_count": 0,
        "observed_span_count": 3,
        "trace_root": h("trace:" + trace_id),
        "tree_algorithm": "rfc6962-mth-sha256-promote-odd-v1",
        "completion_policy": {"type": "root_close_plus_grace", "grace_millis": 30000, "semconv_schema_id": "test.otel.v1"},
        "seal_reason": "grace_elapsed",
        "semantic_claims": True,
        "typed_event_status": "valid",
        "semantic_graph_hash": sha256_canonical(semantic_graph),
        "signal_schema_id": schema,
        "signal_points_micros": signals,
        "state_cap": "white",
    }
    receipt = sign_object(body, INPUT_KEY)
    disclosure = {
        "kind": "coherence_input_disclosure",
        "disclosure_version": "0.1",
        "trace_id": trace_id,
        "semantic_graph": semantic_graph,
        "signal_schema_id": schema,
        "signals": [{"sequence": index, "value_micros": value} for index, value in enumerate(signals)],
    }
    return receipt, disclosure


def write(name: str, value: dict) -> None:
    (VECTORS / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    VECTORS.mkdir(exist_ok=True)
    previous_receipt, previous_disclosure = make_input(graph(), [500_000] * 3, "11" * 16)
    input_receipt, disclosure = make_input(graph(changed=True), [400_000, 500_000, 400_000], "22" * 16)
    derived = issue_measurement_receipt(
        input_receipt,
        disclosure,
        MEASUREMENT_KEY,
        previous_input_receipt=previous_receipt,
        previous_disclosure=previous_disclosure,
        profile=conformance_profile(SCHEMA),
    )
    empty_receipt, empty_disclosure = make_input(graph(empty=True), [], "33" * 16)
    empty_derived = issue_measurement_receipt(empty_receipt, empty_disclosure, MEASUREMENT_KEY)
    checkpoint_anchor_receipt, checkpoint_anchor_disclosure = make_input(claim_window(0, 20), [500_000] * 3, "aa" * 16)
    checkpoint_previous_receipt, checkpoint_previous_disclosure = make_input(claim_window(9, 20), [500_000] * 3, "bb" * 16)
    checkpoint_input_receipt, checkpoint_disclosure = make_input(claim_window(10, 20), [500_000] * 3, "cc" * 16)
    checkpoint_derived = issue_measurement_receipt(
        checkpoint_input_receipt,
        checkpoint_disclosure,
        MEASUREMENT_KEY,
        previous_input_receipt=checkpoint_previous_receipt,
        previous_disclosure=checkpoint_previous_disclosure,
        checkpoint_anchor_input_receipt=checkpoint_anchor_receipt,
        checkpoint_anchor_disclosure=checkpoint_anchor_disclosure,
        profile=conformance_profile(SCHEMA),
    )
    tampered = copy.deepcopy(derived)
    tampered["measurement"]["digest"]["kappa_micros"] += 1

    for name, value in {
        "previous-input-receipt.json": previous_receipt,
        "previous-input-disclosure.json": previous_disclosure,
        "input-receipt.json": input_receipt,
        "input-disclosure.json": disclosure,
        "measurement-receipt.json": derived,
        "empty-input-receipt.json": empty_receipt,
        "empty-input-disclosure.json": empty_disclosure,
        "empty-measurement-receipt.json": empty_derived,
        "checkpoint-anchor-input-receipt.json": checkpoint_anchor_receipt,
        "checkpoint-anchor-input-disclosure.json": checkpoint_anchor_disclosure,
        "checkpoint-previous-input-receipt.json": checkpoint_previous_receipt,
        "checkpoint-previous-input-disclosure.json": checkpoint_previous_disclosure,
        "checkpoint-input-receipt.json": checkpoint_input_receipt,
        "checkpoint-input-disclosure.json": checkpoint_disclosure,
        "checkpoint-measurement-receipt.json": checkpoint_derived,
        "invalid-tampered-measurement.json": tampered,
    }.items():
        write(name, value)


if __name__ == "__main__":
    main()
