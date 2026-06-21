import copy
import unittest

from cole_portable_core.core import conformance_profile
from cole_portable_core.receipt import issue_measurement_receipt, verify_measurement_receipt
from tests.helpers import MEASUREMENT_KEY, graph, make_input


SCHEMA = "test.normalized-signal.v1"


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

    def verify(self, derived=None, receipt=None, disclosure=None, previous_receipt=None, previous_disclosure=None):
        return verify_measurement_receipt(
            derived or self.derived,
            receipt or self.input_receipt,
            disclosure or self.disclosure,
            previous_input_receipt=self.previous_receipt if previous_receipt is None else previous_receipt,
            previous_disclosure=self.previous_disclosure if previous_disclosure is None else previous_disclosure,
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
