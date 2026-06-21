import unittest

from cole_portable_core.canonical import canonical_json, parse_json_strict


class CanonicalTests(unittest.TestCase):
    def test_ascii_escapes_unicode_and_sorts_keys(self):
        self.assertEqual(canonical_json({"z": "caf\u00e9", "a": 1}), b'{"a":1,"z":"caf\\u00e9"}')

    def test_float_rejected(self):
        with self.assertRaises(ValueError):
            canonical_json({"value": 0.5})

    def test_unsafe_integer_rejected(self):
        with self.assertRaises(ValueError):
            canonical_json({"value": 9_007_199_254_740_992})

    def test_duplicate_json_key_rejected(self):
        with self.assertRaises(ValueError):
            parse_json_strict('{"a":1,"a":2}')


if __name__ == "__main__":
    unittest.main()
