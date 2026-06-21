"""The Wire Canon 0.1 input boundary required by COLE Portable Core."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from .canonical import CANONICALIZATION_ID, MAX_SAFE_INTEGER, sha256_canonical, verify_signed_object


HASH256 = re.compile(r"^[0-9a-f]{64}$")
TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]+$")


def _exact(value: Mapping[str, Any], fields: set[str]) -> None:
    if set(value) != fields:
        raise ValueError(f"field mismatch: expected={sorted(fields)} actual={sorted(value)}")


def _hash(value: Any, field: str) -> None:
    if not isinstance(value, str) or not HASH256.fullmatch(value):
        raise ValueError(f"{field} must be lowercase SHA-256 hex")


def validate_semantic_graph(graph: Mapping[str, Any]) -> None:
    if not isinstance(graph, Mapping):
        raise ValueError("semantic_graph must be an object")
    _exact(graph, {"claims", "evidence", "relations"})
    if not all(isinstance(graph[name], list) for name in graph):
        raise ValueError("semantic graph groups must be arrays")

    node_types: dict[str, str] = {}
    claim_ids: list[str] = []
    evidence_ids: list[str] = []
    for claim in graph["claims"]:
        if not isinstance(claim, Mapping):
            raise ValueError("claim must be an object")
        _exact(claim, {"id", "content_hash", "material"})
        node_id = claim["id"]
        if not isinstance(node_id, str) or not SAFE_ID.fullmatch(node_id) or node_id in node_types:
            raise ValueError("claim id must be safe and globally unique")
        _hash(claim["content_hash"], "claim content_hash")
        if not isinstance(claim["material"], bool):
            raise ValueError("claim material must be boolean")
        node_types[node_id] = "Claim"
        claim_ids.append(node_id)

    for evidence in graph["evidence"]:
        if not isinstance(evidence, Mapping):
            raise ValueError("evidence must be an object")
        _exact(evidence, {"id", "content_hash", "observed"})
        node_id = evidence["id"]
        if not isinstance(node_id, str) or not SAFE_ID.fullmatch(node_id) or node_id in node_types:
            raise ValueError("evidence id must be safe and globally unique")
        _hash(evidence["content_hash"], "evidence content_hash")
        if evidence["observed"] is not True:
            raise ValueError("evidence must be directly observed")
        node_types[node_id] = "Evidence"
        evidence_ids.append(node_id)

    if claim_ids != sorted(claim_ids) or evidence_ids != sorted(evidence_ids):
        raise ValueError("semantic graph nodes must be sorted by id")

    relation_keys: list[tuple[str, str, str]] = []
    for relation in graph["relations"]:
        if not isinstance(relation, Mapping):
            raise ValueError("relation must be an object")
        _exact(relation, {"src", "dst", "relation_type"})
        src, dst, relation_type = relation["src"], relation["dst"], relation["relation_type"]
        if src not in node_types or dst not in node_types:
            raise ValueError("relation references a missing node")
        if relation_type == "supports":
            if node_types[src] != "Evidence" or node_types[dst] != "Claim":
                raise ValueError("supports must point from Evidence to Claim")
        elif relation_type == "contradicts":
            if node_types[src] != "Claim" or node_types[dst] != "Claim":
                raise ValueError("contradicts must point between Claims")
        elif relation_type == "depends_on":
            if node_types[dst] != "Claim":
                raise ValueError("depends_on must target a Claim")
        else:
            raise ValueError("unsupported relation type")
        relation_keys.append((src, dst, relation_type))
    if len(relation_keys) != len(set(relation_keys)) or relation_keys != sorted(relation_keys):
        raise ValueError("relations must be unique and sorted")


def validate_coherence_receipt(receipt: Mapping[str, Any]) -> None:
    required = {
        "kind", "receipt_version", "algorithm_id", "canonicalization_id", "spec_uri",
        "attestation", "capture_status", "payload_hash", "signature", "trace_id",
        "capture_loss", "dropped_span_count", "observed_span_count", "trace_root",
        "tree_algorithm", "completion_policy", "seal_reason", "semantic_claims",
        "typed_event_status", "semantic_graph_hash", "signal_schema_id",
        "signal_points_micros", "state_cap",
    }
    if not isinstance(receipt, Mapping):
        raise ValueError("receipt must be an object")
    _exact(receipt, required)
    if receipt["kind"] != "coherence_input_receipt" or receipt["receipt_version"] != "0.1":
        raise ValueError("unsupported Canon input profile")
    if receipt["canonicalization_id"] != CANONICALIZATION_ID:
        raise ValueError("unsupported canonicalization")
    if receipt["attestation"] != "self" or receipt["capture_status"] != "provisional":
        raise ValueError("unsupported trust profile")
    if not isinstance(receipt["algorithm_id"], str) or not receipt["algorithm_id"].isascii() or not receipt["algorithm_id"]:
        raise ValueError("algorithm_id must be non-empty ASCII")
    if not isinstance(receipt["spec_uri"], str) or not receipt["spec_uri"].startswith(("https://", "urn:")):
        raise ValueError("spec_uri must be an HTTPS URI or URN")
    if receipt["semantic_claims"] is not True or receipt["typed_event_status"] != "valid":
        raise ValueError("explicit valid semantics are required")
    if receipt["state_cap"] != "white":
        raise ValueError("Canon input state cap must remain white")
    if not isinstance(receipt["trace_id"], str) or not TRACE_ID.fullmatch(receipt["trace_id"]):
        raise ValueError("invalid trace_id")
    _hash(receipt["semantic_graph_hash"], "semantic_graph_hash")
    _hash(receipt["trace_root"], "trace_root")
    _hash(receipt["payload_hash"], "payload_hash")
    for field in ("dropped_span_count", "observed_span_count"):
        value = receipt[field]
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_SAFE_INTEGER:
            raise ValueError(f"invalid {field}")
    if not isinstance(receipt["capture_loss"], bool) or receipt["capture_loss"] is not (receipt["dropped_span_count"] > 0):
        raise ValueError("capture_loss must agree with dropped_span_count")
    if receipt["tree_algorithm"] != "rfc6962-mth-sha256-promote-odd-v1":
        raise ValueError("unsupported tree algorithm")
    completion = receipt["completion_policy"]
    if not isinstance(completion, Mapping):
        raise ValueError("completion_policy must be an object")
    _exact(completion, {"type", "grace_millis", "semconv_schema_id"})
    if completion["type"] != "root_close_plus_grace":
        raise ValueError("unsupported completion policy")
    if not isinstance(completion["grace_millis"], int) or isinstance(completion["grace_millis"], bool) or not 0 <= completion["grace_millis"] <= MAX_SAFE_INTEGER:
        raise ValueError("invalid grace_millis")
    if not isinstance(completion["semconv_schema_id"], str) or not completion["semconv_schema_id"]:
        raise ValueError("semconv_schema_id is required")
    if receipt["seal_reason"] not in {"grace_elapsed", "shutdown_before_grace_elapsed"}:
        raise ValueError("unsupported seal reason")
    points = receipt["signal_points_micros"]
    if not isinstance(points, list) or any(
        not isinstance(value, int) or isinstance(value, bool) or abs(value) > MAX_SAFE_INTEGER for value in points
    ):
        raise ValueError("signal_points_micros must contain interoperable integers")
    if points and (not isinstance(receipt["signal_schema_id"], str) or not receipt["signal_schema_id"]):
        raise ValueError("signal schema is required with signal points")
    if not points and receipt["signal_schema_id"] is not None:
        raise ValueError("signal schema must be null without signal points")
    if not verify_signed_object(receipt):
        raise ValueError("Canon input signature or payload hash is invalid")


def validate_disclosure(disclosure: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    validate_coherence_receipt(receipt)
    if not isinstance(disclosure, Mapping):
        raise ValueError("disclosure must be an object")
    _exact(disclosure, {"kind", "disclosure_version", "trace_id", "semantic_graph", "signal_schema_id", "signals"})
    if disclosure["kind"] != "coherence_input_disclosure" or disclosure["disclosure_version"] != "0.1":
        raise ValueError("unsupported disclosure profile")
    if disclosure["trace_id"] != receipt["trace_id"]:
        raise ValueError("disclosure trace mismatch")
    validate_semantic_graph(disclosure["semantic_graph"])
    if sha256_canonical(disclosure["semantic_graph"]) != receipt["semantic_graph_hash"]:
        raise ValueError("semantic graph commitment mismatch")
    if disclosure["signal_schema_id"] != receipt["signal_schema_id"]:
        raise ValueError("signal schema mismatch")
    values: list[int] = []
    if not isinstance(disclosure["signals"], list):
        raise ValueError("signals must be an array")
    for sequence, signal in enumerate(disclosure["signals"]):
        if not isinstance(signal, Mapping):
            raise ValueError("signal must be an object")
        _exact(signal, {"sequence", "value_micros"})
        if signal["sequence"] != sequence:
            raise ValueError("signals must be contiguous and zero-based")
        value = signal["value_micros"]
        if not isinstance(value, int) or isinstance(value, bool) or abs(value) > MAX_SAFE_INTEGER:
            raise ValueError("invalid signal value")
        values.append(value)
    if values != receipt["signal_points_micros"]:
        raise ValueError("signal commitment mismatch")
