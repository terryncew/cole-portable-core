import copy
import unittest

from cole_portable_core.core import conformance_profile
from cole_portable_core.receipt import issue_measurement_receipt, verify_measurement_receipt
from tests.helpers import MEASUREMENT_KEY, graph, hash_text, make_input


SCHEMA = "test.normalized-signal.v1"


def claim_window(start: int, count: int) -> dict:
    return {
        "claims": [
            {"id": f"claim_{index:02d}", "content_hash": hash_text(f"claim:{index:02d}"), "material": False}
            for index in range(start, start + count)
        ],
        "evidence": [],
        "relations": [],
    }


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.previous_receipt, self.previous_disclosure = make_input(graph(), [500_000] * 3, trace_id="11" * 16)
        self.input_receipt, self.disclosure = make_input(graph(changed=True), [400_000, 500_000, 400_000])
        self.derived = issue_measurement_receipt(
            self.input_receipt,
            self.disclosure,
            MEASUREMENT_KEY,
            previous_input_receipt=self.previous_receipt,
            previous_disclosure=self.previous_disclosure,
            profile=conformance_profile(SCHEMA),
        )

    def verify(
        self,
        derived=None,
        receipt=None,
        disclosure=None,
        previous_receipt=None,
        previous_disclosure=None,
        checkpoint_anchor_receipt=None,
        checkpoint_anchor_disclosure=None,
    ):
        return verify_measurement_receipt(
            derived or self.derived,
            receipt or self.input_receipt,
            disclosure or self.disclosure,
            previous_input_receipt=self.previous_receipt if previous_receipt is None else previous_receipt,
            previous_disclosure=self.previous_disclosure if previous_disclosure is None else previous_disclosure,
            checkpoint_anchor_input_receipt=checkpoint_anchor_receipt,
            checkpoint_anchor_disclosure=checkpoint_anchor_disclosure,
        )

    def test_valid_measurement_receipt(self):
        self.assertTrue(self.verify())

    def test_graph_substitution_fails(self):
        changed = copy.deepcopy(self.disclosure)
        changed["semantic_graph"]["claims"][0]["content_hash"] = "00" * 32
        self.assertFalse(self.verify(disclosure=changed))

    def test_signal_substitution_fails(self):
        changed = copy.deepcopy(self.disclosure)
        changed["signals"][1]["value_micros"] += 1
        self.assertFalse(self.verify(disclosure=changed))

    def test_derived_metric_tampering_fails(self):
        changed = copy.deepcopy(self.derived)
        changed["measurement"]["digest"]["kappa_micros"] += 1
        self.assertFalse(self.verify(derived=changed))

    def test_previous_state_substitution_fails(self):
        other_receipt, other_disclosure = make_input(graph(empty=True), [500_000] * 3, trace_id="33" * 16)
        self.assertFalse(self.verify(previous_receipt=other_receipt, previous_disclosure=other_disclosure))

    def test_checkpoint_catches_slow_walk_drift(self):
        anchor_receipt, anchor_disclosure = make_input(claim_window(0, 20), [500_000] * 3, trace_id="aa" * 16)
        previous_receipt, previous_disclosure = make_input(claim_window(9, 20), [500_000] * 3, trace_id="bb" * 16)
        current_receipt, current_disclosure = make_input(claim_window(10, 20), [500_000] * 3, trace_id="cc" * 16)
        derived = issue_measurement_receipt(
            current_receipt,
            current_disclosure,
            MEASUREMENT_KEY,
            previous_input_receipt=previous_receipt,
            previous_disclosure=previous_disclosure,
            checkpoint_anchor_input_receipt=anchor_receipt,
            checkpoint_anchor_disclosure=anchor_disclosure,
            profile=conformance_profile(SCHEMA),
        )

        self.assertEqual(derived["measurement"]["status"], "green")
        self.assertEqual(derived["checkpoint"]["anchor_measurement"]["status"], "amber")
        self.assertLess(derived["measurement"]["digest"]["delta_hol_micros"], 350_000)
        self.assertGreaterEqual(derived["checkpoint"]["anchor_measurement"]["digest"]["delta_hol_micros"], 350_000)
        self.assertTrue(
            verify_measurement_receipt(
                derived,
                current_receipt,
                current_disclosure,
                previous_input_receipt=previous_receipt,
                previous_disclosure=previous_disclosure,
                checkpoint_anchor_input_receipt=anchor_receipt,
                checkpoint_anchor_disclosure=anchor_disclosure,
            )
        )

    def test_checkpoint_requires_anchor_for_verification(self):
        anchor_receipt, anchor_disclosure = make_input(claim_window(0, 20), [500_000] * 3, trace_id="aa" * 16)
        previous_receipt, previous_disclosure = make_input(claim_window(9, 20), [500_000] * 3, trace_id="bb" * 16)
        current_receipt, current_disclosure = make_input(claim_window(10, 20), [500_000] * 3, trace_id="cc" * 16)
        derived = issue_measurement_receipt(
            current_receipt,
            current_disclosure,
            MEASUREMENT_KEY,
            previous_input_receipt=previous_receipt,
            previous_disclosure=previous_disclosure,
            checkpoint_anchor_input_receipt=anchor_receipt,
            checkpoint_anchor_disclosure=anchor_disclosure,
            profile=conformance_profile(SCHEMA),
        )

        self.assertFalse(
            verify_measurement_receipt(
                derived,
                current_receipt,
                current_disclosure,
                previous_input_receipt=previous_receipt,
                previous_disclosure=previous_disclosure,
            )
        )
        other_anchor_receipt, other_anchor_disclosure = make_input(claim_window(20, 20), [500_000] * 3, trace_id="dd" * 16)
        self.assertFalse(
            verify_measurement_receipt(
                derived,
                current_receipt,
                current_disclosure,
                previous_input_receipt=previous_receipt,
                previous_disclosure=previous_disclosure,
                checkpoint_anchor_input_receipt=other_anchor_receipt,
                checkpoint_anchor_disclosure=other_anchor_disclosure,
            )
        )

    def test_unknown_derived_field_fails(self):
        changed = copy.deepcopy(self.derived)
        changed["extra"] = True
        self.assertFalse(self.verify(derived=changed))

    def test_silent_input_trust_upgrade_fails(self):
        changed = copy.deepcopy(self.input_receipt)
        changed["attestation"] = "verified"
        self.assertFalse(self.verify(receipt=changed))

    def test_signal_sequence_gap_fails(self):
        changed = copy.deepcopy(self.disclosure)
        changed["signals"][1]["sequence"] = 2
        self.assertFalse(self.verify(disclosure=changed))

    def test_unsorted_graph_fails(self):
        g = graph()
        second = copy.deepcopy(g["claims"][0])
        second["id"] = "claim_0"
        second["content_hash"] = "44" * 32
        g["claims"].append(second)
        receipt, disclosure = make_input(g, [500_000] * 3)
        with self.assertRaises(ValueError):
            issue_measurement_receipt(receipt, disclosure, MEASUREMENT_KEY)

    def test_empty_disclosure_with_no_signal_issues_white(self):
        receipt, disclosure = make_input(graph(empty=True), [])
        derived = issue_measurement_receipt(receipt, disclosure, MEASUREMENT_KEY)
        self.assertEqual(derived["measurement"]["status"], "white")
        self.assertTrue(verify_measurement_receipt(derived, receipt, disclosure))


if __name__ == "__main__":
    unittest.main()
