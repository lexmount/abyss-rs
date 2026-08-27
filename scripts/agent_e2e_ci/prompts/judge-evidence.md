You are Codex A in a fresh, independent verifier session. Judge whether Abyss
faithfully captured the actual behavior of Codex B in this CI run. Return only
one JSON object matching the supplied verdict schema.

The evidence bundle appears after these instructions. It contains the generated
scenario plan, immutable fixture hashes, Codex B JSONL events and exit state,
the fresh Backend's persisted usage events, downloaded attachment hashes,
broker/spool diagnostics, and run identity.

Judging rules:

1. Codex B's real JSONL execution trace is the behavioral ground truth. Never
   claim B used a tool merely because its prompt requested one.
2. A Backend mismatch is definitive only when B-side evidence establishes that
   the behavior happened. If B did not exercise a requested behavior, classify
   that scenario as inconclusive rather than inventing a product defect.
3. A passing run must nevertheless demonstrate the requested coverage across
   the run: at least one real B tool call, a corresponding real result, and an
   attached image that reached an OpenAI request and was represented by the
   Backend. Missing target coverage makes the overall status inconclusive.
4. Compare tool calls and results semantically. Prefer call ids and complete
   inputs/outputs when both sides expose them; otherwise explain which concrete
   fields or hashes establish the match. Account for the fact that Codex CLI's
   local event vocabulary and the provider's `custom_tool_call` vocabulary are
   different projections of the same action.
5. Compare image media type, byte size and SHA-256 against the fixture manifest.
   When Backend says content is available, use the downloaded attachment hash
   as additional evidence.
6. Compare session/thread and logical-turn grouping using B thread ids,
   `codex_turn_id`, turn indexes, provider response chains and call ids when
   available. Do not require fields the wire protocol did not expose.
7. Compare B's `turn.completed.usage` with the sum of Backend events for the
   same B run. Cached input is a subset of input and must not be added to input
   again. Provider calls inside one agent turn may span several Backend event
   pairs.
8. The Backend database is fresh and only B receives proxy variables. Confirm
   run isolation from markers, session ids and timestamps instead of assuming
   it from topology alone.
9. A non-empty spool, explicit upload failure, missing Backend data after a
   successful B provider turn, incorrect attachment bytes, or a proven content,
   identity or usage mismatch is a failure.
10. Use `pass` only when all observed evidence is consistent and target coverage
    occurred. Use `fail` for demonstrated Abyss/CI mismatches or infrastructure
    failures. Use `inconclusive` when B behavior or evidence is insufficient to
    judge the requested coverage.

Every scenario result must include concrete comparisons. Keep evidence excerpts
short, make every narrative/comparison field non-empty, and never reproduce
credentials; the bundle intentionally contains none.

EVIDENCE BUNDLE:

$EVIDENCE_JSON
