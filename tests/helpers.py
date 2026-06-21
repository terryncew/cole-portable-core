from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cole_portable_core.canonical import sha256_canonical, sign_object


INPUT_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32))
MEASUREMENT_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("22" * 32))


def hash_text(value: str) -> str:
    import hashlib
    return hashlib.sha256(value.encode()).hexdigest()


def graph(*, changed: bool = False, empty: bool = False, material: bool = True) -> dict:
    if empty:
        return {"claims": [], "evidence": [], "relations": []}
    claim_hash = hash_text("claim changed" if changed else "claim")
    return {
        "claims": [{"id": "claim_1", "content_hash": claim_hash, "material": material}],
        "evidence": [{"id": "evidence_1", "content_hash": hash_text("evidence"), "observed": True}],
        "relations": [{"src": "evidence_1", "dst": "claim_1", "relation_type": "supports"}],
    }


def make_input(
    semantic_graph: dict,
    signals: list[int],
    *,
    trace_id: str = "22" * 16,
    signal_schema_id: str | None = "test.normalized-signal.v1",
) -> tuple[dict, dict]:
    if not signals:
        signal_schema_id = None
    body = {
        "kind": "coherence_input_receipt",
        "receipt_version": "0.1",
        "algorithm_id": "test-canon-producer-0.1",
        "canonicalization_id": "olp-canonical-json-int-v1",
        "spec_uri": "https://github.com/terryncew/olp-wire-canon",
        "attestation": "self",
        "capture_status": "provisional",
        "trace_id": trace_id,
        "capture_loss": False,
        "dropped_span_count": 0,
        "observed_span_count": 1,
        "trace_root": hash_text("trace:" + trace_id),
        "tree_algorithm": "rfc6962-mth-sha256-promote-odd-v1",
        "completion_policy": {
            "type": "root_close_plus_grace",
            "grace_millis": 30000,
            "semconv_schema_id": "test.otel.v1",
        },
        "seal_reason": "grace_elapsed",
        "semantic_claims": True,
        "typed_event_status": "valid",
        "semantic_graph_hash": sha256_canonical(semantic_graph),
        "signal_schema_id": signal_schema_id,
        "signal_points_micros": signals,
        "state_cap": "white",
    }
    receipt = sign_object(body, INPUT_KEY)
    disclosure = {
        "kind": "coherence_input_disclosure",
        "disclosure_version": "0.1",
        "trace_id": trace_id,
        "semantic_graph": semantic_graph,
        "signal_schema_id": signal_schema_id,
        "signals": [{"sequence": index, "value_micros": value} for index, value in enumerate(signals)],
    }
    return receipt, disclosure
