"""Declare Hermes runtime identity in outbound model request headers."""

_OWNED_HEADERS = frozenset({"x-hermes-session-id", "x-hermes-turn-id"})


def _identifier(value):
    """Accept runtime identifiers that are safe to send as HTTP header values."""
    if not isinstance(value, str) or not value.isascii():
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    return value.strip() or None


def _declare_request(*, request, session_id="", turn_id="", **_context):
    """Use per-call context so parallel sessions never share mutable identity."""
    session = _identifier(session_id)
    if session is None:
        return None
    headers = {
        name: value
        for name, value in (request.get("extra_headers") or {}).items()
        if name.lower() not in _OWNED_HEADERS
    }
    headers["x-hermes-session-id"] = session
    if turn := _identifier(turn_id):
        headers["x-hermes-turn-id"] = turn
    return {"request": {**request, "extra_headers": headers}}


def register(ctx):
    """Register Hermes' supported request middleware without replacing transport."""
    ctx.register_middleware("llm_request", _declare_request)
