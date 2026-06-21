"""COLE Portable Core 2.1 fixed-point measurement equations."""

from __future__ import annotations

from dataclasses import dataclass
from math import isqrt

from .canon import validate_semantic_graph
from .canonical import MAX_SAFE_INTEGER, sha256_canonical


SCALE = 1_000_000
ALGORITHM_ID = "cole-portable-core-2.1-draft"


def reference_profile(signal_schema_id: str | None) -> dict:
    return {
        "profile_id": "cole-reference-prior-1",
        "signal_schema_id": signal_schema_id,
        "calibration_status": "uncalibrated_reference",
        "calibration_corpus_hash": None,
        "calibration_sample_count": 0,
        "smoothing_window": 1,
        "epsilon_window": 10,
        "i_c_micros": 1_000_000,
        "alpha_k_micros": 500_000,
        "alpha_e_micros": 300_000,
        "stability_delta_micros": 10_000,
        "kappa_critical_micros": 850_000,
        "phi_min_micros": 200_000,
        "amber_kappa_micros": 750_000,
        "amber_epsilon_micros": 400_000,
        "amber_dhol_micros": 350_000,
        "dhol_claim_weight_micros": 333_334,
        "dhol_evidence_weight_micros": 333_333,
        "dhol_relation_weight_micros": 333_333,
    }


def conformance_profile(signal_schema_id: str | None) -> dict:
    return {
        **reference_profile(signal_schema_id),
        "profile_id": "synthetic-conformance-only-1",
        "calibration_status": "synthetic_conformance",
        "epsilon_window": 3,
    }


PROFILE_FIELDS = set(reference_profile(None))


def validate_profile(profile: dict) -> None:
    if not isinstance(profile, dict) or set(profile) != PROFILE_FIELDS:
        raise ValueError("profile fields do not match Core 2.1")
    if not isinstance(profile["profile_id"], str) or not profile["profile_id"].isascii() or not profile["profile_id"]:
        raise ValueError("profile_id must be non-empty ASCII")
    schema = profile["signal_schema_id"]
    if schema is not None and (not isinstance(schema, str) or not schema):
        raise ValueError("signal_schema_id must be null or non-empty")
    status = profile["calibration_status"]
    if status not in {"calibrated", "synthetic_conformance", "uncalibrated_reference"}:
        raise ValueError("invalid calibration status")
    corpus_hash = profile["calibration_corpus_hash"]
    if status == "calibrated":
        if not isinstance(corpus_hash, str) or len(corpus_hash) != 64 or any(c not in "0123456789abcdef" for c in corpus_hash):
            raise ValueError("calibrated profiles require a lowercase corpus hash")
        if profile["calibration_sample_count"] < 500:
            raise ValueError("calibrated profiles require at least 500 labeled samples")
    elif corpus_hash is not None or profile["calibration_sample_count"] != 0:
        raise ValueError("uncalibrated profiles cannot claim a calibration corpus")
    for key, value in profile.items():
        if key not in {"profile_id", "signal_schema_id", "calibration_status", "calibration_corpus_hash"}:
            if not isinstance(value, int) or isinstance(value, bool) or abs(value) > MAX_SAFE_INTEGER:
                raise ValueError(f"{key} must be an interoperable integer")
    nonnegative = PROFILE_FIELDS - {"profile_id", "signal_schema_id", "calibration_status", "calibration_corpus_hash"}
    if any(profile[key] < 0 for key in nonnegative):
        raise ValueError("profile integer values must be nonnegative")
    if profile["smoothing_window"] < 1 or profile["epsilon_window"] < 2 or profile["i_c_micros"] < 1:
        raise ValueError("invalid signal windows")
    weights = ("dhol_claim_weight_micros", "dhol_evidence_weight_micros", "dhol_relation_weight_micros")
    if sum(profile[key] for key in weights) != SCALE or any(profile[key] < 0 for key in weights):
        raise ValueError("delta_hol weights must be nonnegative and sum to one")


def _validate_signal(signal: list[int]) -> None:
    if not isinstance(signal, list) or any(
        not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= SCALE for value in signal
    ):
        raise ValueError("Core 2.1 requires normalized integer signal values in [0, 1000000]")


def smooth_signal(signal: list[int], window: int) -> list[int]:
    return [sum(signal[max(0, i - window + 1):i + 1]) // min(window, i + 1) for i in range(len(signal))]


def curvature_point_micros(x0: int, x1: int, x2: int) -> int:
    numerator = abs(x2 - 2 * x1 + x0)
    dx = x1 - x0
    base = SCALE * SCALE + dx * dx
    return numerator * SCALE**3 // (base * isqrt(base))


def curvature_micros(signal: list[int], smoothing_window: int = 1) -> int | None:
    _validate_signal(signal)
    if len(signal) < 3:
        return None
    smoothed = smooth_signal(signal, smoothing_window)
    return max(curvature_point_micros(smoothed[i - 1], smoothed[i], smoothed[i + 1]) for i in range(1, len(smoothed) - 1))


def epsilon_micros(signal: list[int], window: int, smoothing_window: int = 1) -> int | None:
    _validate_signal(signal)
    smoothed = smooth_signal(signal, smoothing_window)
    if len(smoothed) < window:
        return None
    values = []
    for end in range(window, len(smoothed) + 1):
        sample = smoothed[end - window:end]
        total = sum(sample)
        variance_numerator = window * sum(value * value for value in sample) - total * total
        values.append(isqrt(max(0, variance_numerator)) // window)
    return max(values)


def structural_groups(graph: dict) -> dict[str, set[str]]:
    validate_semantic_graph(graph)
    return {
        "claims": {sha256_canonical(item) for item in graph["claims"]},
        "evidence": {sha256_canonical(item) for item in graph["evidence"]},
        "relations": {sha256_canonical(item) for item in graph["relations"]},
    }


def set_drift_micros(current: set[str], previous: set[str]) -> int:
    union = current | previous
    return 0 if not union else len(union - (current & previous)) * SCALE // len(union)


def graph_drift(current: dict, previous: dict | None, profile: dict) -> tuple[int | None, dict]:
    if previous is None:
        return None, {"claim_micros": None, "evidence_micros": None, "relation_micros": None}
    current_groups, previous_groups = structural_groups(current), structural_groups(previous)
    vector = {
        "claim_micros": set_drift_micros(current_groups["claims"], previous_groups["claims"]),
        "evidence_micros": set_drift_micros(current_groups["evidence"], previous_groups["evidence"]),
        "relation_micros": set_drift_micros(current_groups["relations"], previous_groups["relations"]),
    }
    weighted_square = (
        profile["dhol_claim_weight_micros"] * vector["claim_micros"] ** 2
        + profile["dhol_evidence_weight_micros"] * vector["evidence_micros"] ** 2
        + profile["dhol_relation_weight_micros"] * vector["relation_micros"] ** 2
    ) // SCALE
    return isqrt(weighted_square), vector


def support_coverage(graph: dict) -> dict:
    validate_semantic_graph(graph)
    material = {claim["id"] for claim in graph["claims"] if claim["material"]}
    observed = {evidence["id"] for evidence in graph["evidence"] if evidence["observed"]}
    supported = {
        relation["dst"] for relation in graph["relations"]
        if relation["relation_type"] == "supports" and relation["src"] in observed and relation["dst"] in material
    }
    unsupported = material - supported
    return {
        "claim_count": len(material),
        "supported_claim_count": len(supported),
        "unsupported_claim_count": len(unsupported),
        "ucr_micros": None if not material else len(unsupported) * SCALE // len(material),
    }


def phi_star_micros(kappa: int, epsilon: int, profile: dict) -> int:
    denominator = SCALE + profile["alpha_k_micros"] * kappa // SCALE + profile["alpha_e_micros"] * epsilon // SCALE + profile["stability_delta_micros"]
    return profile["i_c_micros"] * SCALE // denominator


@dataclass(frozen=True)
class Measurement:
    semantic_graph_hash: str
    digest: dict
    status: str
    support: dict
    drift_vector: dict

    def as_dict(self) -> dict:
        return {
            "semantic_graph_hash": self.semantic_graph_hash,
            "digest": self.digest,
            "status": self.status,
            "support": self.support,
            "drift_vector": self.drift_vector,
        }


def evaluate(graph: dict, signal: list[int], previous_graph: dict | None, profile: dict) -> Measurement:
    validate_profile(profile)
    validate_semantic_graph(graph)
    if profile["signal_schema_id"] is None and signal:
        raise ValueError("signal values require a profile signal schema")
    kappa = curvature_micros(signal, profile["smoothing_window"])
    epsilon = epsilon_micros(signal, profile["epsilon_window"], profile["smoothing_window"])
    delta_hol, drift_vector = graph_drift(graph, previous_graph, profile)
    phi = None if kappa is None or epsilon is None else phi_star_micros(kappa, epsilon, profile)
    vkd = None if phi is None else min(profile["kappa_critical_micros"] - kappa, phi - profile["phi_min_micros"])
    if profile["calibration_status"] not in {"calibrated", "synthetic_conformance"} or None in {kappa, epsilon, delta_hol}:
        status = "white"
    elif vkd < 0:
        status = "red"
    elif kappa >= profile["amber_kappa_micros"] or epsilon >= profile["amber_epsilon_micros"] or delta_hol >= profile["amber_dhol_micros"]:
        status = "amber"
    else:
        status = "green"
    digest = {
        "phi_star_micros": phi,
        "kappa_micros": kappa,
        "epsilon_micros": epsilon,
        "delta_hol_micros": delta_hol,
        "vkd_micros": vkd,
    }
    for value in digest.values():
        if value is not None and abs(value) > MAX_SAFE_INTEGER:
            raise ValueError("derived measurement exceeds interoperable integer range")
    return Measurement(sha256_canonical(graph), digest, status, support_coverage(graph), drift_vector)
