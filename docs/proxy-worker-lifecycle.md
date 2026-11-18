# Event-driven proxy worker lifecycle

Task: `tun.md`. Baseline: `378032f` (endpoint 1.6.1).

A Linux TUN packet task can fail and close its flow channel. The outer ingress
worker then drains existing connections and exits. Previously the proxy retained
`Started` until the next start, stop, or status call inspected `is_finished()`.
A supervisor now observes worker completion and publishes the stopped state
without any control-plane request. The public REST lifecycle remains
`running`/`stopped`; no SDK or protocol changes are required.

Each ingress run has a UUID and a supervisor that exclusively owns its join
handle. The supervisor handles normal completion, cancellation and panic, updates
the matching runtime to stopped, and then publishes the outcome through a watch
channel. State is changed before completion is published, so a successful stop
cannot return before that transition. The supervisor retains only a weak state
reference, allowing the last service handle to drop and close the worker's
shutdown channel. Late completion for an older UUID cannot stop a newer run.

A separate operation mutex serializes start and stop. Ingress binding runs
outside the state mutex; worker creation and state publication share one short
critical section so an immediate exit cannot precede publication. Stop transitions the
private runtime into `Stopping`, signals shutdown, releases the state mutex and
awaits completion. Status remains readable during connection draining and
continues to report running until the worker has released its ingress. A
cancelled stop request leaves its shutdown and supervision active; a later start
waits for that stopping run before binding. The supervisor never needs the
operation mutex. This prevents a stop/join/state-lock cycle and prevents two
runs from overlapping during normal stop/restart.

Task failures are shared through `Arc<JoinError>` so explicit stop retains its
existing task-error response while the supervisor can log the same failure.
This affects broker-internal error ownership only; JSON error text and HTTP
status codes are unchanged.

Validation covers autonomous state updates without calling status, worker panic
and cancellation, status reads during draining, cancellation of stop, serialized
restart and stale completion. Existing drain-timeout tests remain in place.
Run broker unit/integration tests, explicit proxy and TUN/WireGuard black-box
checks, formatting, Clippy and workspace tests. Rebuild immutable broker and
delivery binaries and repeat real codex/dsh capture, delivery and backend query
proofs. Keep command results and the rendered HTML report in the persistent
`task-artifacts/tun/supervision` directory alongside the earlier TUN evidence.
