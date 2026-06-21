#!/usr/bin/env node
// Independent Node.js verifier for Canon inputs and COLE Core 2.1 measurements.

import fs from "node:fs";
import { createHash, createPublicKey, verify as ed25519Verify } from "node:crypto";

const SCALE = 1_000_000n;
const SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const SAFE_ID = /^[A-Za-z0-9._:-]+$/;

function parseJsonStrict(text) {
  let offset = 0;
  const skip = () => { while (/[\t\n\r ]/.test(text[offset] ?? "")) offset += 1; };
  const string = () => {
    if (text[offset] !== '"') throw new Error(`expected string at ${offset}`);
    const start = offset++;
    let escaped = false;
    while (offset < text.length) {
      const char = text[offset++];
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') return JSON.parse(text.slice(start, offset));
    }
    throw new Error("unterminated string");
  };
  const value = () => {
    skip();
    if (text[offset] === '"') return string();
    if (text[offset] === "{") {
      offset += 1;
      const result = Object.create(null);
      const keys = new Set();
      skip();
      if (text[offset] === "}") { offset += 1; return result; }
      while (true) {
        skip();
        const key = string();
        if (keys.has(key)) throw new Error(`duplicate key ${key}`);
        keys.add(key);
        skip();
        if (text[offset++] !== ":") throw new Error("expected colon");
        result[key] = value();
        skip();
        const delimiter = text[offset++];
        if (delimiter === "}") return result;
        if (delimiter !== ",") throw new Error("expected comma");
      }
    }
    if (text[offset] === "[") {
      offset += 1;
      const result = [];
      skip();
      if (text[offset] === "]") { offset += 1; return result; }
      while (true) {
        result.push(value());
        skip();
        const delimiter = text[offset++];
        if (delimiter === "]") return result;
        if (delimiter !== ",") throw new Error("expected comma");
      }
    }
    for (const [word, parsed] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(word, offset)) { offset += word.length; return parsed; }
    }
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(offset));
    if (!match) throw new Error(`invalid value at ${offset}`);
    offset += match[0].length;
    if (/[.eE]/.test(match[0])) throw new Error("floats forbidden");
    const parsed = Number(match[0]);
    if (!Number.isSafeInteger(parsed)) throw new Error("unsafe integer");
    return parsed;
  };
  const result = value();
  skip();
  if (offset !== text.length) throw new Error("trailing JSON");
  return result;
}

function quoteAscii(value) {
  let output = '"';
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 8) output += "\\b";
    else if (code === 9) output += "\\t";
    else if (code === 10) output += "\\n";
    else if (code === 12) output += "\\f";
    else if (code === 13) output += "\\r";
    else if (code === 34) output += '\\"';
    else if (code === 92) output += "\\\\";
    else if (code < 32 || code > 126) output += `\\u${code.toString(16).padStart(4, "0")}`;
    else output += String.fromCharCode(code);
  }
  return `${output}"`;
}

function encode(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return quoteAscii(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("unsafe canonical number");
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (Array.isArray(value)) return `[${value.map(encode).join(",")}]`;
  if (typeof value !== "object") throw new Error("unsupported canonical value");
  for (const key of Object.keys(value)) if (!/^[\x00-\x7f]*$/.test(key)) throw new Error("non-ASCII key");
  return `{${Object.keys(value).sort().map((key) => `${quoteAscii(key)}:${encode(value[key])}`).join(",")}}`;
}

const canonical = (value) => Buffer.from(encode(value), "ascii");
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const sha256Canonical = (value) => sha256(canonical(value));
const exact = (value, fields) => {
  const actual = Object.keys(value).sort().join("\0");
  const expected = [...fields].sort().join("\0");
  if (actual !== expected) throw new Error("field mismatch");
};

function verifyEnvelope(receipt) {
  try {
    const { payload_hash: payloadHash, signature, ...body } = receipt;
    exact(signature, ["algorithm", "public_key", "value"]);
    if (!HEX64.test(payloadHash) || signature.algorithm !== "Ed25519" || !HEX64.test(signature.public_key) || !HEX128.test(signature.value)) return false;
    const bytes = canonical(body);
    if (sha256(bytes) !== payloadHash) return false;
    const key = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(signature.public_key, "hex")]), format: "der", type: "spki" });
    return ed25519Verify(null, bytes, key, Buffer.from(signature.value, "hex"));
  } catch { return false; }
}

function validateGraph(graph) {
  exact(graph, ["claims", "evidence", "relations"]);
  if (![graph.claims, graph.evidence, graph.relations].every(Array.isArray)) throw new Error("graph arrays required");
  const types = new Map();
  const claimIds = [];
  const evidenceIds = [];
  for (const claim of graph.claims) {
    exact(claim, ["id", "content_hash", "material"]);
    if (!SAFE_ID.test(claim.id) || types.has(claim.id) || !HEX64.test(claim.content_hash) || typeof claim.material !== "boolean") throw new Error("invalid claim");
    types.set(claim.id, "Claim"); claimIds.push(claim.id);
  }
  for (const evidence of graph.evidence) {
    exact(evidence, ["id", "content_hash", "observed"]);
    if (!SAFE_ID.test(evidence.id) || types.has(evidence.id) || !HEX64.test(evidence.content_hash) || evidence.observed !== true) throw new Error("invalid evidence");
    types.set(evidence.id, "Evidence"); evidenceIds.push(evidence.id);
  }
  if (claimIds.join("\0") !== [...claimIds].sort().join("\0") || evidenceIds.join("\0") !== [...evidenceIds].sort().join("\0")) throw new Error("unsorted nodes");
  const keys = [];
  for (const relation of graph.relations) {
    exact(relation, ["src", "dst", "relation_type"]);
    const { src, dst, relation_type: type } = relation;
    if (!types.has(src) || !types.has(dst)) throw new Error("missing relation target");
    if (type === "supports" && (types.get(src) !== "Evidence" || types.get(dst) !== "Claim")) throw new Error("invalid supports");
    if (type === "contradicts" && (types.get(src) !== "Claim" || types.get(dst) !== "Claim")) throw new Error("invalid contradicts");
    if (type === "depends_on" && types.get(dst) !== "Claim") throw new Error("invalid depends_on");
    if (!["supports", "contradicts", "depends_on"].includes(type)) throw new Error("unknown relation");
    keys.push(`${src}\0${dst}\0${type}`);
  }
  if (new Set(keys).size !== keys.length || keys.join("\u0001") !== [...keys].sort().join("\u0001")) throw new Error("relations not unique and sorted");
}

const CANON_FIELDS = [
  "kind", "receipt_version", "algorithm_id", "canonicalization_id", "spec_uri", "attestation", "capture_status", "payload_hash", "signature",
  "trace_id", "capture_loss", "dropped_span_count", "observed_span_count", "trace_root", "tree_algorithm", "completion_policy", "seal_reason",
  "semantic_claims", "typed_event_status", "semantic_graph_hash", "signal_schema_id", "signal_points_micros", "state_cap",
];

function validateInput(receipt, disclosure) {
  exact(receipt, CANON_FIELDS);
  if (!verifyEnvelope(receipt) || receipt.kind !== "coherence_input_receipt" || receipt.receipt_version !== "0.1") throw new Error("invalid Canon receipt");
  if (receipt.canonicalization_id !== "olp-canonical-json-int-v1" || receipt.attestation !== "self" || receipt.capture_status !== "provisional") throw new Error("invalid Canon trust profile");
  if (receipt.semantic_claims !== true || receipt.typed_event_status !== "valid" || receipt.state_cap !== "white") throw new Error("invalid semantic admission");
  if (!HEX64.test(receipt.semantic_graph_hash) || !HEX64.test(receipt.trace_root) || !/^[0-9a-f]{32}$/.test(receipt.trace_id)) throw new Error("invalid Canon hashes");
  if (typeof receipt.capture_loss !== "boolean" || !Number.isSafeInteger(receipt.dropped_span_count) || receipt.dropped_span_count < 0 || receipt.capture_loss !== (receipt.dropped_span_count > 0)) throw new Error("invalid capture loss");
  if (!Number.isSafeInteger(receipt.observed_span_count) || receipt.observed_span_count < 0 || receipt.tree_algorithm !== "rfc6962-mth-sha256-promote-odd-v1") throw new Error("invalid trace profile");
  exact(receipt.completion_policy, ["type", "grace_millis", "semconv_schema_id"]);
  if (receipt.completion_policy.type !== "root_close_plus_grace" || !Number.isSafeInteger(receipt.completion_policy.grace_millis) || receipt.completion_policy.grace_millis < 0 || typeof receipt.completion_policy.semconv_schema_id !== "string" || !receipt.completion_policy.semconv_schema_id) throw new Error("invalid completion policy");
  if (!Array.isArray(receipt.signal_points_micros) || !receipt.signal_points_micros.every(Number.isSafeInteger)) throw new Error("invalid Canon signals");
  if ((receipt.signal_points_micros.length === 0) !== (receipt.signal_schema_id === null)) throw new Error("invalid signal schema");
  exact(disclosure, ["kind", "disclosure_version", "trace_id", "semantic_graph", "signal_schema_id", "signals"]);
  if (disclosure.kind !== "coherence_input_disclosure" || disclosure.disclosure_version !== "0.1" || disclosure.trace_id !== receipt.trace_id) throw new Error("invalid disclosure profile");
  validateGraph(disclosure.semantic_graph);
  if (sha256Canonical(disclosure.semantic_graph) !== receipt.semantic_graph_hash || disclosure.signal_schema_id !== receipt.signal_schema_id) throw new Error("disclosure commitment mismatch");
  const values = disclosure.signals.map((item, index) => {
    exact(item, ["sequence", "value_micros"]);
    if (item.sequence !== index || !Number.isSafeInteger(item.value_micros)) throw new Error("invalid disclosed signal");
    return item.value_micros;
  });
  if (encode(values) !== encode(receipt.signal_points_micros)) throw new Error("signal commitment mismatch");
  return { graph: disclosure.semantic_graph, signal: values };
}

const bi = (value) => BigInt(value);
function bigintSqrt(value) {
  if (value < 0n) throw new Error("negative sqrt");
  if (value < 2n) return value;
  let x = 1n << (BigInt(value.toString(2).length) + 1n) / 2n;
  while (true) { const y = (x + value / x) / 2n; if (y >= x) return x; x = y; }
}
function number(value) { if (value > SAFE || value < -SAFE) throw new Error("derived unsafe integer"); return Number(value); }
function smooth(signal, window) {
  return signal.map((_, index) => {
    const start = Math.max(0, index - window + 1);
    const sample = signal.slice(start, index + 1);
    return sample.reduce((a, b) => a + b, 0n) / BigInt(sample.length);
  });
}
function curvature(signal, window) {
  if (signal.length < 3) return null;
  const values = smooth(signal.map(bi), window);
  let maximum = 0n;
  for (let i = 1; i < values.length - 1; i += 1) {
    const numerator = values[i + 1] - 2n * values[i] + values[i - 1];
    const dx = values[i] - values[i - 1];
    const base = SCALE * SCALE + dx * dx;
    const point = (numerator < 0n ? -numerator : numerator) * SCALE ** 3n / (base * bigintSqrt(base));
    if (point > maximum) maximum = point;
  }
  return maximum;
}
function epsilon(signal, window, smoothingWindow) {
  const values = smooth(signal.map(bi), smoothingWindow);
  if (values.length < window) return null;
  let maximum = 0n;
  for (let end = window; end <= values.length; end += 1) {
    const sample = values.slice(end - window, end);
    const total = sample.reduce((a, b) => a + b, 0n);
    const sumSquares = sample.reduce((a, b) => a + b * b, 0n);
    const value = bigintSqrt(BigInt(window) * sumSquares - total * total) / BigInt(window);
    if (value > maximum) maximum = value;
  }
  return maximum;
}
function groups(graph) {
  return {
    claims: new Set(graph.claims.map(sha256Canonical)),
    evidence: new Set(graph.evidence.map(sha256Canonical)),
    relations: new Set(graph.relations.map(sha256Canonical)),
  };
}
function driftSet(current, previous) {
  const union = new Set([...current, ...previous]);
  if (union.size === 0) return 0n;
  let intersection = 0;
  for (const item of current) if (previous.has(item)) intersection += 1;
  return BigInt(union.size - intersection) * SCALE / BigInt(union.size);
}
function graphDrift(current, previous, profile) {
  if (previous === null) return [null, { claim_micros: null, evidence_micros: null, relation_micros: null }];
  const a = groups(current); const b = groups(previous);
  const claim = driftSet(a.claims, b.claims); const evidence = driftSet(a.evidence, b.evidence); const relation = driftSet(a.relations, b.relations);
  const square = (bi(profile.dhol_claim_weight_micros) * claim * claim + bi(profile.dhol_evidence_weight_micros) * evidence * evidence + bi(profile.dhol_relation_weight_micros) * relation * relation) / SCALE;
  return [bigintSqrt(square), { claim_micros: number(claim), evidence_micros: number(evidence), relation_micros: number(relation) }];
}
function support(graph) {
  const material = new Set(graph.claims.filter((item) => item.material).map((item) => item.id));
  const observed = new Set(graph.evidence.filter((item) => item.observed).map((item) => item.id));
  const supported = new Set(graph.relations.filter((item) => item.relation_type === "supports" && observed.has(item.src) && material.has(item.dst)).map((item) => item.dst));
  return {
    claim_count: material.size,
    supported_claim_count: supported.size,
    unsupported_claim_count: material.size - supported.size,
    ucr_micros: material.size === 0 ? null : Math.floor((material.size - supported.size) * 1_000_000 / material.size),
  };
}
function evaluate(graph, signal, previous, profile) {
  if (signal.some((item) => !Number.isInteger(item) || item < 0 || item > 1_000_000)) throw new Error("signal outside Core domain");
  const kappa = curvature(signal, profile.smoothing_window);
  const eps = epsilon(signal, profile.epsilon_window, profile.smoothing_window);
  const [delta, vector] = graphDrift(graph, previous, profile);
  const phi = kappa === null || eps === null ? null : bi(profile.i_c_micros) * SCALE / (SCALE + bi(profile.alpha_k_micros) * kappa / SCALE + bi(profile.alpha_e_micros) * eps / SCALE + bi(profile.stability_delta_micros));
  const vkd = phi === null ? null : (bi(profile.kappa_critical_micros) - kappa < phi - bi(profile.phi_min_micros) ? bi(profile.kappa_critical_micros) - kappa : phi - bi(profile.phi_min_micros));
  let status = "white";
  if (["calibrated", "synthetic_conformance"].includes(profile.calibration_status) && kappa !== null && eps !== null && delta !== null) {
    if (vkd < 0n) status = "red";
    else if (kappa >= bi(profile.amber_kappa_micros) || eps >= bi(profile.amber_epsilon_micros) || delta >= bi(profile.amber_dhol_micros)) status = "amber";
    else status = "green";
  }
  return {
    semantic_graph_hash: sha256Canonical(graph),
    digest: {
      phi_star_micros: phi === null ? null : number(phi),
      kappa_micros: kappa === null ? null : number(kappa),
      epsilon_micros: eps === null ? null : number(eps),
      delta_hol_micros: delta === null ? null : number(delta),
      vkd_micros: vkd === null ? null : number(vkd),
    },
    status,
    support: support(graph),
    drift_vector: vector,
  };
}

const PROFILE_FIELDS = [
  "profile_id", "signal_schema_id", "calibration_status", "calibration_corpus_hash", "calibration_sample_count",
  "smoothing_window", "epsilon_window", "i_c_micros", "alpha_k_micros", "alpha_e_micros", "stability_delta_micros",
  "kappa_critical_micros", "phi_min_micros", "amber_kappa_micros", "amber_epsilon_micros", "amber_dhol_micros",
  "dhol_claim_weight_micros", "dhol_evidence_weight_micros", "dhol_relation_weight_micros",
];
function validateProfile(profile) {
  exact(profile, PROFILE_FIELDS);
  if (typeof profile.profile_id !== "string" || !profile.profile_id || !["calibrated", "synthetic_conformance", "uncalibrated_reference"].includes(profile.calibration_status)) throw new Error("invalid profile identity");
  if (profile.signal_schema_id !== null && (typeof profile.signal_schema_id !== "string" || !profile.signal_schema_id)) throw new Error("invalid profile signal schema");
  for (const field of PROFILE_FIELDS.filter((field) => !["profile_id", "signal_schema_id", "calibration_status", "calibration_corpus_hash"].includes(field))) {
    if (!Number.isSafeInteger(profile[field]) || profile[field] < 0) throw new Error(`invalid profile integer ${field}`);
  }
  if (profile.smoothing_window < 1 || profile.epsilon_window < 2 || profile.i_c_micros < 1) throw new Error("invalid profile windows");
  if (profile.dhol_claim_weight_micros + profile.dhol_evidence_weight_micros + profile.dhol_relation_weight_micros !== 1_000_000) throw new Error("invalid drift weights");
  if (profile.calibration_status === "calibrated") {
    if (!HEX64.test(profile.calibration_corpus_hash) || profile.calibration_sample_count < 500) throw new Error("invalid calibrated profile");
  } else if (profile.calibration_corpus_hash !== null || profile.calibration_sample_count !== 0) throw new Error("invalid uncalibrated claim");
}

function verifyDerived(derived, currentReceipt, currentDisclosure, previousReceipt = null, previousDisclosure = null) {
  const current = validateInput(currentReceipt, currentDisclosure);
  const previous = previousReceipt === null ? null : validateInput(previousReceipt, previousDisclosure);
  exact(derived, ["kind", "receipt_version", "algorithm_id", "canonicalization_id", "spec_uri", "attestation", "input_receipt_hash", "input_trace_id", "previous_input_receipt_hash", "profile", "measurement", "payload_hash", "signature"]);
  if (!verifyEnvelope(derived) || derived.kind !== "cole_measurement_receipt" || derived.receipt_version !== "0.1-draft") return false;
  if (derived.algorithm_id !== "cole-portable-core-2.1-draft" || derived.canonicalization_id !== "olp-canonical-json-int-v1" || derived.attestation !== "self") return false;
  if (derived.input_receipt_hash !== currentReceipt.payload_hash || derived.input_trace_id !== currentReceipt.trace_id) return false;
  if (derived.previous_input_receipt_hash !== (previousReceipt?.payload_hash ?? null)) return false;
  validateProfile(derived.profile);
  if (derived.profile.signal_schema_id !== currentReceipt.signal_schema_id) return false;
  return encode(evaluate(current.graph, current.signal, previous?.graph ?? null, derived.profile)) === encode(derived.measurement);
}

function read(path) { return parseJsonStrict(fs.readFileSync(path, "utf8")); }

if (process.argv.length !== 5 && process.argv.length !== 7) {
  console.error("usage: node verify-node.mjs INPUT DISCLOSURE MEASUREMENT [PREVIOUS_INPUT PREVIOUS_DISCLOSURE]");
  process.exit(2);
}
try {
  const currentReceipt = read(process.argv[2]);
  const currentDisclosure = read(process.argv[3]);
  const derived = read(process.argv[4]);
  const previousReceipt = process.argv.length === 7 ? read(process.argv[5]) : null;
  const previousDisclosure = process.argv.length === 7 ? read(process.argv[6]) : null;
  if (!verifyDerived(derived, currentReceipt, currentDisclosure, previousReceipt, previousDisclosure)) throw new Error("verification failed");
  console.log(`verified ${derived.payload_hash}`);
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
