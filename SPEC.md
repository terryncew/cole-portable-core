# COLE Portable Core 2.1 Draft

## 1. Scope

COLE Portable Core consumes a valid OLP Wire Canon 0.1
`coherence_input_receipt` and a matching `coherence_input_disclosure`. It emits
a separately signed derived measurement that references the Canon input's
`payload_hash`.

The Core measures the admitted graph and disclosed operational signal. It does
not establish the truth of a claim, the accuracy of evidence, the identity of
the producer, or the predictive validity of an uncalibrated profile.

## 2. Input verification

Before measurement, an implementation MUST:

1. verify the Canon input profile, payload hash, and Ed25519 signature;
2. verify the disclosure trace identifier and semantic graph hash;
3. verify the signal schema and contiguous disclosed values against the signed
   `signal_points_micros` array;
4. reject unknown fields, duplicate JSON keys, floating-point values, unsafe
   integers, unsorted graph groups, and invalid typed relations.

For drift, the preceding input receipt and disclosure MUST pass the same checks.
The derived receipt records that preceding input's `payload_hash`.

For long-running sessions, an implementation MAY also issue a checkpoint
measurement. A checkpoint compares the current graph against an explicit anchor
Canon input, such as the first receipt in the run or a later signed
re-baseline. The anchor input receipt and disclosure MUST pass the same checks.
Checkpoint verification MUST NOT require replaying the full chain.

## 3. Fixed-point domain

All numeric inputs and outputs use integer micros where `1.0 = 1_000_000`.
Operational signals MUST lie in `[0, 1_000_000]`. Canon permits a broader safe
integer domain; this narrower range is part of the Core 2.1 algorithm.

### 3.1 Curvature

For consecutive signal points `x0`, `x1`, `x2`:

```text
numerator   = abs(x2 - 2*x1 + x0)
dx          = x1 - x0
base        = SCALE^2 + dx^2
kappa_point = floor(numerator * SCALE^3 / (base * isqrt(base)))
```

`kappa_micros` is the maximum point curvature after the signed profile's
trailing moving-average smoothing. Fewer than three values produces `null`.

### 3.2 Epsilon

For every complete trailing window of size `n`:

```text
variance_numerator = n*sum(x^2) - sum(x)^2
window_std          = floor(isqrt(variance_numerator) / n)
```

`epsilon_micros` is the maximum complete-window value. An incomplete signal
history produces `null`.

### 3.3 Graph drift

Claims, evidence, and relations are independently represented as sets of
SHA-256 hashes over their exact Canon objects. Each component is Jaccard drift:

```text
drift(A,B) = floor((|A union B| - |A intersection B|) * SCALE / |A union B|)
```

An empty union has zero drift. `delta_hol_micros` is the integer square root of
the signed profile's weighted sum of squared component drifts. Without a
preceding verified graph, drift is `null`.

### 3.4 Effective coherence and viability

```text
phi_star = floor(I_c*SCALE /
  (SCALE + alpha_k*kappa/SCALE + alpha_e*epsilon/SCALE + stability_delta))

vkd = min(kappa_critical - kappa, phi_star - phi_min)
```

If curvature or epsilon is unavailable, both values are `null`.

## 4. UCR diagnostic

Material claims count as supported when an admitted `supports` relation points
from an observed evidence node to that claim. UCR is the fraction of material
claims without such support. With no material claims, UCR is `null` while the
operational Core may continue to compute.

This is admitted graph coverage. It is not evidence truth verification.

## 5. State policy

The bundled `uncalibrated_reference` profile emits only `white`. A profile may
claim `calibrated` only when it includes a lowercase SHA-256 corpus hash and at
least 500 labeled samples. The `synthetic_conformance` profile is reserved for
tests and vectors.

For calibrated or synthetic profiles with complete inputs:

- `red`: VKD is below zero;
- `amber`: curvature, epsilon, or graph drift reaches its signed threshold;
- `green`: the complete measurement remains within those thresholds;
- `white`: inputs are incomplete or the profile is uncalibrated.

## 6. Derived receipt

The signed body contains the algorithm and canonicalization identifiers, input
and preceding input hashes, an optional checkpoint, full profile, five-number
digest, UCR diagnostic, drift vector, and state. Ed25519 signs the integer-only
canonical JSON body.

When present, `checkpoint` contains:

- `anchor_input_receipt_hash`: the anchor Canon input `payload_hash`;
- `anchor_measurement`: the same deterministic measurement shape recomputed
  from the current input against the anchor graph.

Normal receipts use `checkpoint: null` and compare only against the preceding
input. Periodic checkpoint receipts compare against both the preceding input and
the anchor input, bounding slow-walk drift while preserving O(1) verification.
Changing the anchor requires an explicit signed re-baseline receipt at a higher
protocol layer; Core 2.1 never silently updates the anchor.

Derived receipts MUST NOT mutate the Canon receipt or upgrade its `self` /
`provisional` trust labels.
