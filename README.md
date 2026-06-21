# cole-portable-core

Deterministic derived coherence measurement for admitted OLP Wire Canon inputs.

`cole-portable-core` verifies a signed `coherence_input_receipt` and its
hash-bound disclosure, computes the COLE Portable Core 2.1 fixed-point digest,
and emits a separately signed `cole_measurement_receipt` tied to the input
receipt's `payload_hash`.

It does not alter the capture receipt, infer semantics from ordinary spans, or
claim that disclosed evidence is true. The bundled reference profile is
uncalibrated and therefore emits only `white`.

## Measurement

The derived digest contains five integer-micro values:

- `kappa_micros`: discrete operational curvature.
- `epsilon_micros`: maximum rolling signal standard deviation.
- `delta_hol_micros`: weighted claim/evidence/relation graph drift.
- `phi_star_micros`: effective coherence under curvature and noise.
- `vkd_micros`: viability margin.

UCR is reported separately as admitted claim-support coverage. It does not feed
`kappa`, `epsilon`, `phi_star`, or `vkd`.

## Use

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cole_portable_core import issue_measurement_receipt

key = Ed25519PrivateKey.generate()
derived = issue_measurement_receipt(input_receipt, disclosure, key)
```

For graph drift, also pass the preceding signed Canon input and disclosure:

```python
derived = issue_measurement_receipt(
    input_receipt,
    disclosure,
    key,
    previous_input_receipt=previous_receipt,
    previous_disclosure=previous_disclosure,
)
```

## Verify

```bash
python -m pip install -e .
python scripts/generate_vectors.py
python -m unittest discover -s tests -v
node verify-node.mjs \
  vectors/input-receipt.json \
  vectors/input-disclosure.json \
  vectors/measurement-receipt.json \
  vectors/previous-input-receipt.json \
  vectors/previous-input-disclosure.json
```

The Node verifier is independent of the Python implementation. It parses JSON
strictly, verifies both Canon signatures and disclosure commitments, recomputes
the Core 2.1 equations with `BigInt`, and verifies the derived signature.

## Boundaries

- Wire Canon 0.1 remains the normative capture contract.
- Core inputs must use normalized integer signals in `[0, 1_000_000]`.
- Missing signal or prior state produces unavailable (`null`) measurements and
  a `white` state where applicable.
- A calibrated profile requires a lowercase corpus hash and at least 500
  labeled samples.
- The synthetic conformance profile exists only to test state transitions.
- Controllers, OWA arbitration, and legacy OLR/1.4L logic are outside this repo.

See [SPEC.md](SPEC.md) for the exact equations and trust boundary.
