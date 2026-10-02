# AIOps Incident Intelligence & Triage

AIOps Incident Intelligence & Triage is a local incident-management system that groups operational
log events into incidents, assigns deterministic severity and routing, and presents sanitized
evidence with lifecycle state and optional validated advisory analysis. It helps operators review
and triage repeated operational events. This is a portfolio demonstration, not a production-ready
incident-management system.

## Architecture

```text
Synthetic fixtures / explicit OS collector
  -> normalization -> sensitive-data redaction -> stable fingerprint
  -> noise filtering / deduplication -> bounded component correlation
  -> incident formation -> deterministic severity and routing
  -> optional advisory analysis -> strict Pydantic contracts
  -> SQLite events / incidents / runs -> FastAPI + local reviewer
  -> frozen offline evaluation + CI
```

The root `main.py` is the FastAPI entry point (`uvicorn main:app`); the explicit cross-platform
collector lives in `aiops/collectors.py`, and the supported CLI is `python -m aiops.cli`. The
locally authored reliability policy examples at `evaluation/fixtures/logs_example.txt` explain the
impact thresholds; evaluation labels remain a separate frozen contract dataset.

## Reproduce the offline demo

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then from the repository:

```sh
uv python install 3.13
uv sync --locked
uv run --locked python -m aiops.cli demo --db demo.sqlite3
uv run --locked uvicorn main:app --host 127.0.0.1 --port 8001
```

Open `http://127.0.0.1:8001/` for the local reviewer or `/docs` for the API schema.
Click **Ingest synthetic demo**: six fixture events produce three incidents (database P0 with
three observations, storage P0 with one, application P4 with one). One normal instrumentation event is filtered;
one repeat is deduplicated; two observations correlate. Zero model or network calls are needed.
The API uses `incidents.sqlite3`; the CLI command above uses its separate named demo database.
Replaying the same fixtures produces no new incidents or analyzer calls. To inspect an independent
fresh demo, select a new CLI database filename.

The dashboard shows severity, routing reasons, component, status, event counts, timestamps,
redacted evidence, analysis state and latest run metrics. All evidence is rendered as text.
It labels deterministic diagnostics separately from advisory analysis and supports explicit
lifecycle changes.

## API

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/health` | Local service health; default analysis mode |
| POST | `/events/ingest` | Validated event batch; explicit analyzer choice |
| POST | `/demo` | Fixed safe fixtures, analysis disabled |
| GET | `/incidents` | Incident queue |
| GET | `/incidents/{id}` | Incident details |
| GET | `/incidents/{id}/events` | Sanitized event relationships, including repeats |
| PATCH | `/incidents/{id}/status` | Explicit lifecycle transition |
| GET | `/runs` | Latest 100 run states and metrics |
| POST | `/collect/system` | Disabled by default; explicit enabled collection only |

Example ingestion body:

```json
{
  "events": [{
    "timestamp": "2026-01-01T00:00:00Z",
    "source": "api",
    "component": "database",
    "message": "Commit quorum lost; writes are being rejected"
  }],
  "analyzer": "none"
}
```

Requests reject unknown fields and naive timestamps. Batches are limited to 500 events,
each message to 4096 characters, and request bodies to 2.5 MB. Invalid request responses omit
submitted values. The app does not collect host logs or contact an analyzer on startup.

## Severity, routing and correlation

P0 marks a broad hard outage or credible integrity breach; P1 marks a major service-objective breach
or impaired recovery path; P2 marks bounded user impact; P3 marks an approaching guardrail; P4 keeps
unmatched context for review; P5 filters routine telemetry. These demonstration thresholds are not
verified business impact. Python rules own final severity and routing; models cannot override them.
Allowed departments are application, network, infrastructure, system_admin, database and security.

The fingerprint hashes normalized source, component and sanitized message signature, replacing
standalone numeric values with `#`. Different occurrences keep separate event IDs. Exact event ID
replays are idempotent. A matching fingerprint within a 300-second incident span counts as a
duplicate observation; it increments event count but adds no repeat evidence snippet or analysis.
Different signatures from the same source/component correlate into an active incident when the
combined timestamp span remains at most 300 seconds. Different components/sources stay separate.
This is a transparent heuristic, not ML correlation. The pipeline window is configurable in Python.

`events_retained` counts non-noise, nonduplicate signatures. `correlated_event_count` counts new
observations attached to existing incidents, including duplicates. `llm_calls` counts analyzer
invocations (including mock and failed invocations), not individual HTTP retry attempts.
`llm_calls_avoided` counts event-level opportunities collapsed or skipped relative to naive
one-call-per-event processing. Only newly formed incidents can trigger analysis, once per incident.
Later evidence does not reanalyze existing incidents; analysis therefore describes formation evidence.

Statuses are open, investigating, resolved and suppressed. Open can become investigating/resolved/
suppressed; investigating can become resolved/suppressed; resolved/suppressed can explicitly reopen.
Novel signatures after closure form a new incident. Same-window duplicates remain attached to the
original incident without reopening it. Exact replays remain deduplicated across restarts.

## Optional collection and analysis

Collect real host logs only when explicitly intended:

```sh
uv run --locked python -m aiops.cli collect --db host.sqlite3
```

The collector uses `journalctl` on Linux, `log show` on macOS and `wevtutil` on Windows.
Commands use argument arrays, no shell, a ten-second deadline, bounded 128 KB output and up to
500 records. Collection errors become typed failures and failed run state, never operational events.
The HTTP collector is disabled in `main:app`; programmatic `create_app(allow_system_collection=True)`
enables the explicit endpoint. It returns no raw host logs. Collection remains disabled on startup.
Collector timestamps are collection time; multiline messages are treated as separate lines.

An offline mock is available without credentials:

```sh
uv run --locked python -m aiops.cli demo --db mock.sqlite3 --analysis mock
```

For explicitly requested external analysis, set `OPENROUTER_API_KEY` in the process environment
and optionally `OPENROUTER_MODEL` (default `openai/gpt-4o-mini`), then:

```sh
uv run --locked python -m aiops.cli demo --db advisory.sqlite3 --analysis openrouter
```

No `.env` file is loaded automatically. `.env.example` contains placeholders only.
The OpenRouter adapter receives redacted evidence without tools. It uses a five-second connect
timeout, fifteen-second HTTP phase timeouts, at most two transport attempts and a 64 KB response
limit. Timeouts are per phase, not a strict whole-request deadline. HTTP errors are not retried.
Every response must satisfy `IncidentAnalysis`, including constrained departments and confidence.
Invalid/unavailable analysis leaves the deterministic incident intact with a safe failure code.
Model text is redacted again before persistence. Suggested diagnostics/remediation are advisory
and must be reviewed by an operator. No commands or remediation actions are executed.

## Verify

```sh
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest -q --basetemp=.test-tmp
uv run --locked python -m compileall -q aiops main.py scripts tests
uv run --locked python -c "import main, aiops.collectors"
uv run --locked python -m aiops.evaluate
uv run --locked python -m scripts.offline_e2e
uv run --locked python -m scripts.secret_check
git diff --check
```

The locked Python 3.13 environment is the primary installation path. Dependencies are defined in
`pyproject.toml` and resolved in `uv.lock`; there is no separate contradictory requirements list.
GitHub Actions installs from the lock and performs these checks without credentials.
Tests/evaluation/E2E block application socket connections; only Python's Windows internal socketpair
setup is permitted. HTTP adapter tests use in-process mock transports. No live model is tested.

The GitHub Actions workflow **Offline contracts** runs on every push and pull request using the
locked environment and the verification commands above. See the repository's Actions history for
the latest hosted result. Observed offline contract results and limitations are in
[docs/evaluation.md](docs/evaluation.md).
See [docs/security.md](docs/security.md) for the redaction and privacy boundary.

## Limitations

This local service has no authentication, tenant isolation, production retention policy, encryption
at rest, migrations, automatic remediation, or production telemetry integration. Bind to loopback
and run one worker. SQLite and an in-process lock suit a small demo, not distributed ingestion;
model calls execute synchronously inside the ingestion transaction. Queue listing is unpaginated.
Rules and redaction patterns are finite; arbitrary unlabelled secrets or hostnames can evade them.
Numeric fingerprinting may merge distinct problems, and broad component correlation may join
unrelated events. P4 unmatched events are deliberately retained for inspection. Incident snapshots
cap representative snippets at 20; linked sanitized observations remain queryable. There is no
dedicated lifecycle audit trail or on-demand reanalysis endpoint. The frozen dataset is small and
does not measure production incident accuracy. OS command mapping is tested; live OS permissions
and live OpenRouter behavior are not verified. The locked Starlette HTTPX test client currently
emits one upstream deprecation warning; tests still pass.
