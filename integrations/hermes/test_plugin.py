"""Exercise the plugin's public registration and request callback contract."""

import copy
import unittest

import abyss


class Registration:
    def register_middleware(self, kind, callback):
        assert kind == "llm_request"
        self.callback = callback


class HermesPluginTests(unittest.TestCase):
    def setUp(self):
        self.registration = Registration()
        abyss.register(self.registration)

    def test_runtime_identity_is_per_request_and_preserves_provider_fields(self):
        request = {
            "model": "test",
            "input": [{"role": "user", "content": "hello"}],
            "extra_headers": {
                "Authorization": "test-only",
                "X-Hermes-Session-Id": "stale",
            },
        }
        original = copy.deepcopy(request)
        for session, turn in [
            ("session-a", "turn-1"),
            ("session-b", "turn-2"),
            ("session-a", "turn-1"),
        ]:
            result = self.registration.callback(
                request=request, session_id=session, turn_id=turn
            )["request"]
            self.assertEqual(result["input"], request["input"])
            self.assertEqual(
                result["extra_headers"],
                {
                    "Authorization": "test-only",
                    "x-hermes-session-id": session,
                    "x-hermes-turn-id": turn,
                },
            )
        self.assertEqual(request, original)

    def test_missing_turn_removes_a_stale_turn_but_preserves_session(self):
        result = self.registration.callback(
            request={"extra_headers": {"X-Hermes-Turn-Id": "stale"}},
            session_id="session-a",
        )["request"]
        self.assertEqual(result["extra_headers"], {"x-hermes-session-id": "session-a"})

    def test_missing_or_invalid_session_does_not_invent_identity(self):
        for session in [None, "", "  ", "a\r\nb", "a\x00b", "非ASCII"]:
            with self.subTest(session=session):
                self.assertIsNone(
                    self.registration.callback(request={}, session_id=session)
                )


if __name__ == "__main__":
    unittest.main()
