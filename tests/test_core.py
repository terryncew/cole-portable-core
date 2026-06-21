import unittest

from cole_portable_core.core import (
    conformance_profile,
    curvature_micros,
    epsilon_micros,
    evaluate,
    reference_profile,
    validate_profile,
)
from tests.helpers import graph


SCHEMA = "test.normalized-signal.v1"


class CoreTests(unittest.TestCase):
    def test_flat_signal_has_zero_curvature(self):
        self.assertEqual(curvature_micros([500_000] * 3), 0)

    def test_curvature_preserves_values_above_one(self):
        self.assertGreater(curvature_micros([0, 700_000, 0]), 750_000)

    def test_noise_sets_epsilon(self):
        self.assertGreater(epsilon_micros([0, 1_000_000, 0], 3), 0)

    def test_out_of_domain_signal_rejected(self):
        with self.assertRaises(ValueError):
            curvature_micros([0, 1_000_001, 0])

    def test_stable_supported_graph_is_green_under_synthetic_profile(self):
        g = graph()
        result = evaluate(g, [500_000] * 3, g, conformance_profile(SCHEMA))
        self.assertEqual(result.status, "green")
        self.assertEqual(result.digest["epsilon_micros"], 0)
        self.assertEqual(result.digest["delta_hol_micros"], 0)
        self.assertEqual(result.support["ucr_micros"], 0)

    def test_changed_graph_has_drift(self):
        result = evaluate(graph(changed=True), [500_000] * 3, graph(), conformance_profile(SCHEMA))
        self.assertGreater(result.digest["delta_hol_micros"], 350_000)

    def test_cold_start_is_white(self):
        self.assertEqual(evaluate(graph(), [500_000] * 3, None, conformance_profile(SCHEMA)).status, "white")

    def test_reference_profile_always_white(self):
        g = graph()
        self.assertEqual(evaluate(g, [500_000] * 10, g, reference_profile(SCHEMA)).status, "white")

    def test_calibrated_profile_requires_corpus_and_500_samples(self):
        profile = reference_profile(SCHEMA)
        profile["calibration_status"] = "calibrated"
        with self.assertRaises(ValueError):
            validate_profile(profile)

    def test_empty_graph_with_signal_keeps_core_operational(self):
        g = graph(empty=True)
        result = evaluate(g, [500_000] * 3, g, conformance_profile(SCHEMA))
        self.assertEqual(result.status, "green")
        self.assertIsNone(result.support["ucr_micros"])

    def test_empty_graph_without_signal_is_white(self):
        g = graph(empty=True)
        result = evaluate(g, [], g, reference_profile(None))
        self.assertEqual(result.status, "white")
        self.assertIsNone(result.digest["kappa_micros"])
        self.assertIsNone(result.digest["epsilon_micros"])
        self.assertIsNone(result.digest["phi_star_micros"])
        self.assertIsNone(result.digest["vkd_micros"])
        self.assertEqual(result.digest["delta_hol_micros"], 0)


if __name__ == "__main__":
    unittest.main()
