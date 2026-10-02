"""Local reviewer API. No collection or network access on startup."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse

from aiops.collectors import SystemLogCollector
from aiops.models import (
    CollectionResult,
    Incident,
    IngestRequest,
    LifecycleRequest,
    NormalizedEvent,
    RunMetrics,
    RunState,
)
from aiops.pipeline import Pipeline
from aiops.sources import synthetic_events
from aiops.store import Store


def create_app(
    db_path: str = "incidents.sqlite3", allow_system_collection: bool = False
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.store = Store(db_path)
        app.state.pipeline = Pipeline(app.state.store)
        yield
        app.state.store.close()

    app = FastAPI(title="AIOps Incident Intelligence", lifespan=lifespan)

    @app.middleware("http")
    async def bounded_body(request: Request, call_next):
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 2_500_000:
                return JSONResponse(status_code=413, content={"error": "request_too_large"})
        request._body = bytes(body)
        return await call_next(request)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, error):
        # Default FastAPI validation errors echo raw sensitive input; do not do that.
        return JSONResponse(status_code=422, content={"error": "invalid_request"})

    @app.exception_handler(Exception)
    async def internal_error(request, error):
        return JSONResponse(status_code=500, content={"error": "internal_error"})

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": "local", "analysis_default": "none"}

    @app.post("/events/ingest", response_model=RunState)
    def ingest(body: IngestRequest) -> RunState:
        return app.state.pipeline.ingest(body)

    @app.post("/demo", response_model=RunState)
    def demo() -> RunState:
        return app.state.pipeline.ingest(IngestRequest(events=synthetic_events()))

    @app.get("/incidents", response_model=list[Incident])
    def incidents() -> list[Incident]:
        return app.state.store.incidents()

    @app.get("/incidents/{incident_id}", response_model=Incident)
    def get_incident(incident_id: str) -> Incident:
        result = app.state.store.get(incident_id)
        if result is None:
            raise HTTPException(404, "incident_not_found")
        return result

    @app.get("/incidents/{incident_id}/events", response_model=list[NormalizedEvent])
    def events(incident_id: str) -> list[NormalizedEvent]:
        get_incident(incident_id)
        return app.state.store.events(incident_id)

    @app.patch("/incidents/{incident_id}/status", response_model=Incident)
    def status(incident_id: str, body: LifecycleRequest) -> Incident:
        try:
            result = app.state.store.transition(incident_id, body.status)
        except ValueError:
            raise HTTPException(409, "invalid_lifecycle_transition") from None
        if result is None:
            raise HTTPException(404, "incident_not_found")
        return result

    @app.get("/runs", response_model=list[RunState])
    def runs() -> list[RunState]:
        return app.state.store.runs()

    @app.post("/collect/system", response_model=CollectionResult)
    def collect() -> CollectionResult:
        if not allow_system_collection:
            raise HTTPException(403, "system_collection_disabled")
        result = SystemLogCollector().collect()
        if result.error:
            now = datetime.now(UTC)
            with app.state.store.lock, app.state.store.db:
                app.state.store.save_run(
                    RunState(
                        run_id=uuid4().hex,
                        started_at=now,
                        completed_at=now,
                        metrics=RunMetrics(),
                        incident_ids=[],
                        status="collection_failed",
                    )
                )
            return result
        app.state.pipeline.ingest(IngestRequest(events=result.events))
        # No raw host logs in API responses, even on explicit collection.
        return CollectionResult(truncated=result.truncated)

    @app.get("/", response_class=HTMLResponse)
    def reviewer():
        return HTMLResponse(
            Path(__file__).with_name("reviewer.html").read_text(encoding="utf-8"),
            headers={
                "Content-Security-Policy": "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
            },
        )

    return app
