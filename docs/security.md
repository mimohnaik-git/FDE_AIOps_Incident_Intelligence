# Safety and privacy boundary

Raw messages exist transiently in collector/request memory. Normalization makes timestamps UTC,
collapses whitespace and maps untrusted source/component labels to known demonstration buckets.
Deterministic redaction runs before fingerprinting, SQLite writes and model access. It replaces
labelled credentials, bearer values, common provider key formats, email addresses, IPv4/IPv6,
user-directory paths, labelled host identifiers, URLs and JWT-like strings. Rules are conservative
demonstration patterns, not a complete data-loss-prevention system.

Persisted events contain sanitized text, fingerprints and redaction counts. Incident evidence
records its redaction policy. Raw OS messages are not exposed through the API. Raw collection
errors/stderr and exception details are discarded. Validation error responses do not echo inputs.
Process credentials are used only in external request headers; neither prompts nor SQLite receive
environment contents. The application never reads the user's `.env`.

Logs and model responses are untrusted. A log asking to print `OPENROUTER_API_KEY` stays evidence
text. It cannot change the analyzer selection, invoke tools, read environment variables or execute
commands. The model has no execution tools. This does not guarantee that a language model will
ignore every adversarial phrase; deterministic Python decisions and strict output validation limit
what advisory output can affect. All model text is redacted again before storage. Dashboard content
uses `textContent`, avoiding HTML execution from evidence or analysis. Diagnostics still require
human review.

Collection is explicit only. Output memory, command duration and event count are bounded.
Collector failures are typed and cannot contain events. Partial output is marked truncated.
OpenRouter calls have bounded retries, response size and HTTP phase timeouts; errors produce
fixed failure codes. No adapter exception or HTTP header is persisted.

`python -m scripts.secret_check` scans Git-tracked and nonignored files, reports file/line locations
and never prints matched secret values. It does not open `.env`; if tracking exposes that filename,
the scanner reports it as a violation. `.env` remains ignored and untracked. This scanner uses a
finite credential-pattern set and is not proof that the repository contains no conceivable secret.
Human-readable test sentinels are not real credentials.

The server is for a single local reviewer. Do not expose it publicly without authentication,
authorization, rate limits, stronger privacy controls, an audit trail and deployment review.
