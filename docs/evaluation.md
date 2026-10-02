# Frozen offline contract evaluation

`evaluation/cases.json` is a first-principles set of service reliability scenarios with independently
written expected labels. It is not generated from runtime output and does not estimate production
accuracy. The cases cover routine filtering, broad unavailability, data integrity, queue and replica
pressure, duplicate grouping, bounded correlation, cross-component routing, redaction, collector
failure, invalid or unavailable advisory analysis, untrusted text and correlation-window limits.

`python -m aiops.evaluate` creates fresh in-memory databases per case. It uses no credentials and
blocks application networking. The malformed-response case exercises the actual OpenRouter adapter
through an HTTPX mock transport; missing credentials exercise safe fallback without a request.
Redaction checks inspect persisted event/incident contracts and model-bound payloads against fixed
synthetic sentinels. Prompt-injection evidence remains data and cannot retrieve process environment
values.

Reproduce the contract evaluation and end-to-end offline run using the exact locked commands in the
README. These are local contract checks, not a production accuracy estimate. Live OS permissions and
live advisory-provider behavior remain outside this offline evaluation.
