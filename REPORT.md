# openline-otel-js 0.1 Draft Verification Report

## Implemented

- OLP Canon integer-only canonical JSON with strict duplicate-key parsing
- Native Node Ed25519 signing and verification
- Strict validation for all four Wire Canon receipt profiles
- OTel-compatible span processor with root-plus-grace sealing
- Signed late-span and capture-loss amendment chaining
- Explicit typed graph admission and hash-bound COLE disclosure
- Exact BigInt timestamp and IEEE-754 telemetry normalization

## Verified locally

- 13 Node tests pass
- Node verifies every signed Python receipt vector used by Canon 0.1
- Python verifies all four Node-produced receipt kinds
- Python independently recomputes the Node trace Merkle root
- Python verifies the Node amendment chain
- Python reproduces the Node disclosure commitments
- Tampering, duplicate JSON keys, floats, unsafe Canon integers, non-ASCII
  keys, cycles, and unknown receipt fields are rejected

## Remaining release gate

The npm registry was unavailable in the build environment. The processor was
tested against structurally faithful `ReadableSpan` fixtures. A live SDK test
is included and GitHub Actions installs the current OpenTelemetry packages
before running it across Node 20, 22, and 24 with Python 3.11 and 3.12.

Status: reciprocal Canon implementation complete; external SDK gate pending.
