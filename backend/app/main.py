import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from zoneinfo import ZoneInfo

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.analysis.llm import LocalModelError, assert_local_url, enrich as run_enrich, ollama_health
from app.db import close, get_event, get_settings, init_db, list_devices, list_events, purge, save_llm, save_llm_error, save_settings, summary
from app.ingest import ingest_lines
from app.serialize import event_view
from app.syslog_server import SyslogServer

logging.basicConfig(level=logging.WARNING)
DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
ENGINES = {"rules", "llm", "hybrid"}


def _on_syslog(line):
    ingest_lines([line], "syslog", "syslog")


@asynccontextmanager
async def lifespan(app):
    init_db()
    server = SyslogServer(_on_syslog)
    app.state.syslog = server
    settings = get_settings()
    if settings.get("syslog_enabled") == "true":
        await server.start(int(settings["syslog_port"]))
    yield
    await server.stop()
    close()


app = FastAPI(title="Loggy", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


class SettingsUpdate(BaseModel):
    engine: Optional[str] = None
    ollama_url: Optional[str] = None
    ollama_model: Optional[str] = None
    timezone: Optional[str] = None
    syslog_port: Optional[int] = None
    syslog_enabled: Optional[bool] = None


def _zone(name):
    try:
        return ZoneInfo(name)
    except Exception:
        raise HTTPException(status_code=400, detail="Zona horaria no válida")


def _window(from_local, to_local, tz):
    start = _local_to_iso(from_local, tz, end=False) if from_local else None
    end = _local_to_iso(to_local, tz, end=True) if to_local else None
    return start, end


def _local_to_iso(value, tz, end):
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise HTTPException(status_code=400, detail="Fecha no válida")
    if end and parsed.second == 0 and parsed.microsecond == 0 and len(value) <= 16:
        parsed = parsed.replace(second=59, microsecond=999000)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=tz)
    return parsed.astimezone(ZoneInfo("UTC")).isoformat(timespec="milliseconds")


def _event_for_llm(row):
    import json

    return {
        "criticality": row["criticality"],
        "vendor": row["vendor"],
        "device": row["device"],
        "mnemonic": row["mnemonic"],
        "title": row["title"],
        "message": row["message"],
        "raw": row["raw"],
        "explanation": row["explanation"],
        "probable_cause": row["probable_cause"],
        "actions": json.loads(row["actions_json"] or "[]"),
        "fields": json.loads(row["fields_json"] or "{}"),
    }


@app.get("/api/health")
def health():
    return {"ok": True}


@app.get("/api/settings")
def read_settings():
    return get_settings()


@app.put("/api/settings")
async def update_settings(body: SettingsUpdate):
    current = get_settings()
    previous_port = current["syslog_port"]
    previous_enabled = current["syslog_enabled"]
    if body.engine is not None:
        if body.engine not in ENGINES:
            raise HTTPException(status_code=400, detail="Motor no válido")
        current["engine"] = body.engine
    if body.ollama_url is not None:
        try:
            current["ollama_url"] = assert_local_url(body.ollama_url)
        except LocalModelError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    if body.ollama_model is not None:
        model = body.ollama_model.strip()
        if not model or len(model) > 120:
            raise HTTPException(status_code=400, detail="Modelo no válido")
        current["ollama_model"] = model
    if body.timezone is not None:
        _zone(body.timezone)
        current["timezone"] = body.timezone
    if body.syslog_port is not None:
        if not 0 <= int(body.syslog_port) <= 65535:
            raise HTTPException(status_code=400, detail="Puerto no válido")
        current["syslog_port"] = str(int(body.syslog_port))
    if body.syslog_enabled is not None:
        current["syslog_enabled"] = "true" if body.syslog_enabled else "false"
    current["syslog_host"] = "127.0.0.1"
    save_settings(current)
    if current["syslog_port"] != previous_port or current["syslog_enabled"] != previous_enabled:
        server = app.state.syslog
        if current["syslog_enabled"] == "true":
            await server.start(int(current["syslog_port"]))
        else:
            await server.stop()
            server.error = None
    return {"settings": get_settings(), "syslog": _syslog_status()}


@app.get("/api/ollama")
async def ollama_status():
    return await ollama_health(get_settings())


@app.get("/api/syslog")
def syslog_status():
    return _syslog_status()


def _syslog_status():
    settings = get_settings()
    server = getattr(app.state, "syslog", None)
    running = bool(server and server.running)
    return {
        "enabled": settings.get("syslog_enabled") == "true",
        "host": "127.0.0.1",
        "port": server.port if server and server.port else int(settings["syslog_port"]),
        "configured_port": int(settings["syslog_port"]),
        "running": running,
        "udp": running,
        "tcp": running,
        "error": None if server is None else server.error,
        "received": 0 if server is None else server.received,
    }


@app.post("/api/upload")
async def upload(files: List[UploadFile] = File(...)):
    if not files:
        raise HTTPException(status_code=400, detail="No hay archivos")
    totals = {"accepted": 0, "parsed": 0, "unparsed": 0, "files": []}
    for item in files:
        name = os.path.basename(item.filename or "archivo")
        totals["files"].append(name)
        pending = []
        buffer = b""
        while True:
            chunk = await item.read(256 * 1024)
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer:
                raw, buffer = buffer.split(b"\n", 1)
                pending.append(raw.decode("utf-8", errors="replace"))
                if len(pending) >= 400:
                    _accumulate(totals, ingest_lines(pending, "file", name))
                    pending = []
        if buffer.strip():
            pending.append(buffer.decode("utf-8", errors="replace"))
        if pending:
            _accumulate(totals, ingest_lines(pending, "file", name))
        await item.close()
    return totals


def _accumulate(totals, result):
    totals["accepted"] += result["accepted"]
    totals["parsed"] += result["parsed"]
    totals["unparsed"] += result["unparsed"]


@app.get("/api/events")
def events(
    criticality: Optional[str] = None,
    vendor: Optional[str] = None,
    device: Optional[str] = None,
    q: Optional[str] = None,
    order: str = "desc",
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    from_local: Optional[str] = None,
    to_local: Optional[str] = None,
):
    settings = get_settings()
    if order not in ("asc", "desc"):
        order = "desc"
    if criticality == "":
        criticality = None
    start, end = _window(from_local, to_local, _zone(settings["timezone"]))
    rows, total = list_events(
        criticality=criticality or None,
        vendor=vendor or None,
        device=device or None,
        q=(q or "").strip() or None,
        start=start,
        end=end,
        order=order,
        limit=limit,
        offset=offset,
    )
    return {
        "events": [event_view(row, settings["engine"]) for row in rows],
        "total": total,
        "engine": settings["engine"],
    }


@app.get("/api/summary")
def events_summary(
    criticality: Optional[str] = None,
    vendor: Optional[str] = None,
    device: Optional[str] = None,
    q: Optional[str] = None,
    from_local: Optional[str] = None,
    to_local: Optional[str] = None,
):
    settings = get_settings()
    start, end = _window(from_local, to_local, _zone(settings["timezone"]))
    data = summary(
        criticality=criticality or None,
        vendor=vendor or None,
        device=device or None,
        q=(q or "").strip() or None,
        start=start,
        end=end,
    )
    data["engine"] = settings["engine"]
    return data


@app.get("/api/devices")
def devices():
    return {"devices": list_devices()}


@app.get("/api/events/{event_id}")
async def event_detail(event_id: int, enrich: bool = True, refresh: bool = False):
    row = get_event(event_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Evento no encontrado")
    settings = get_settings()
    engine = settings["engine"]
    if enrich and engine in ("llm", "hybrid") and (refresh or not row["llm_enhanced"]):
        outcome = await run_enrich(_event_for_llm(row), settings, engine)
        if outcome["ok"]:
            save_llm(event_id, outcome["explanation"], outcome["probable_cause"], outcome["actions"])
        else:
            save_llm_error(event_id, outcome["error"])
        row = get_event(event_id)
    return event_view(row, engine, include_raw=True)


@app.post("/api/purge")
def purge_events():
    purge()
    server = getattr(app.state, "syslog", None)
    if server is not None:
        server.received = 0
    return {"ok": True}


if DIST.exists():
    app.mount("/", StaticFiles(directory=DIST, html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
