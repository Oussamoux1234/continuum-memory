import json
import unittest

from continuum_memory.transport import MAX_JSON_DEPTH, decode_frame


class JsonDepthTest(unittest.TestCase):
    def nested(self, levels, kind):
        payload = "0"
        for level in range(levels):
            if kind == "array" or (kind == "mixed" and level % 2):
                payload = "[" + payload + "]"
            else:
                payload = '{"a":' + payload + "}"
        return payload.encode()

    def test_arrays_objects_and_mixed_containers_at_limit(self):
        for kind in ("array", "object", "mixed"):
            with self.subTest(kind=kind):
                decoded = decode_frame(self.nested(MAX_JSON_DEPTH, kind))
                for _ in range(MAX_JSON_DEPTH):
                    decoded = decoded[0] if isinstance(decoded, list) else decoded["a"]
                self.assertEqual(decoded, 0)

    def test_arrays_objects_and_mixed_containers_past_limit_fail_uniformly(self):
        for kind in ("array", "object", "mixed"):
            for depth in (MAX_JSON_DEPTH + 1, 1500):
                with self.subTest(kind=kind, depth=depth):
                    with self.assertRaisesRegex(ValueError, "^JSON nesting exceeds limit$"):
                        decode_frame(self.nested(depth, kind))

    def test_quoted_delimiters_escaped_quotes_and_backslashes_are_data(self):
        values = ['[{' * 1500, '}]' * 1500, '\\"[\\]"{}', '"' + '\\' * 17 + "[{]"]
        for value in values:
            with self.subTest(value=value[:20]):
                encoded = json.dumps({"text": value}).encode()
                self.assertEqual(decode_frame(encoded), {"text": value})

    def test_malformed_strings_and_unbalanced_containers_still_fail(self):
        for raw in (b'{"text":"unterminated}', b"[{]}", b"][[", b'{"text":"\\x"}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    decode_frame(raw)


if __name__ == "__main__":
    unittest.main()
