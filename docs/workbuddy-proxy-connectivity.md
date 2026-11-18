# WorkBuddy daemon TLS routing

WorkBuddy 5.11.3 on macOS launches its daemon as Electron with
`--disable-warning=ExperimentalWarning`, the absolute daemon script path,
and `--stdio`. The model client and daemon share a signing identity and use
the same gateway. The daemon rejects the broker's certificate, so its existing
passthrough rule matches both the application ID and the exact daemon entry
point. When the broker failed to recognize the warning option, the entry point
was absent and the subsequent gateway interception rule took effect.

The Node/Electron entry resolver can skip a nonempty warning selector attached
with `=`. The warning selector occupies a single argument and leaves the next
argument available for normal script resolution. Unknown options still stop
resolution. The broker uses the resulting entry path in the existing policy
evaluation. This requires no change to trust stores, rule order, the flow
protocol or saved policies.

Parser tests cover the observed command and unsupported command forms. The
[macOS framed ingress test](../crates/abyss-broker/tests/scenarios/process_entry_points.rs)
sends TLS traffic through the broker with a real source PID. A client trusting
only the origin must receive its HTTP response for the matching daemon. The
sibling script, other application ID and relocated installation remain subject
to the configured interception policy.

Desktop distributions need a released broker containing this change. Installing
a desktop package pinned to an older endpoint continues to use the older parser.
