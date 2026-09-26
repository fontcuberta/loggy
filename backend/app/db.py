import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from app.parsing.timeutil import isoformat_utc

_LOCK = threading.Lock()
_CONN = None

DEFAULTS = None


def db_path():
    configured = os.environ.get("LOGGY_DB")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parent.parent / "data" / "loggy.db"


def close():
    global _CONN
    with _LOCK:
        if _CONN is not None:
            _CONN.close()
            _CONN = None


def connect():
    global _CONN
    if _CONN is None:
        path = db_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        _CONN = sqlite3.connect(str(path), check_same_thread=False)
        _CONN.row_factory = sqlite3.Row
        _CONN.execute("PRAGMA journal_mode=WAL")
        _CONN.execute("PRAGMA synchronous=NORMAL")
    return _CONN


def default_settings():
    return {
        "engine": "hybrid",
        "ollama_url": "http://127.0.0.1:11434",
        "ollama_model": "llama3.1:8b",
        "timezone": "Europe/Madrid",
        "syslog_host": "127.0.0.1",
        "syslog_port": os.environ.get("LOGGY_SYSLOG_PORT", "5514"),
        "syslog_enabled": "true",
    }


def init_db():
    with _LOCK:
        conn = connect()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                timestamp_estimated INTEGER NOT NULL DEFAULT 0,
                tz_assumed INTEGER NOT NULL DEFAULT 0,
                device TEXT NOT NULL,
                vendor TEXT NOT NULL,
                severity_original TEXT,
                severity_num INTEGER,
                mnemonic TEXT,
                message TEXT NOT NULL,
                raw TEXT NOT NULL,
                fields_json TEXT NOT NULL,
                source TEXT NOT NULL,
                source_name TEXT NOT NULL,
                unparsed INTEGER NOT NULL DEFAULT 0,
                criticality TEXT NOT NULL,
                title TEXT NOT NULL,
                explanation TEXT NOT NULL,
                probable_cause TEXT NOT NULL,
                actions_json TEXT NOT NULL,
                signature_id TEXT,
                llm_explanation TEXT,
                llm_probable_cause TEXT,
                llm_actions_json TEXT,
                llm_enhanced INTEGER NOT NULL DEFAULT 0,
                llm_error TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_vendor ON events(vendor);
            CREATE INDEX IF NOT EXISTS idx_events_criticality ON events(criticality);
            CREATE INDEX IF NOT EXISTS idx_events_device ON events(device);
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        for key, value in default_settings().items():
            conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO NOTHING",
                (key, value),
            )
        conn.commit()


def get_settings():
    with _LOCK:
        conn = connect()
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    settings = default_settings()
    settings.update({row["key"]: row["value"] for row in rows})
    settings["syslog_host"] = "127.0.0.1"
    return settings


def save_settings(settings):
    with _LOCK:
        conn = connect()
        for key, value in settings.items():
            conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(value)),
            )
        conn.commit()


def insert_events(events):
    if not events:
        return 0
    now = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    rows = []
    for event in events:
        rows.append(
            (
                isoformat_utc(event["timestamp"]),
                1 if event.get("timestamp_estimated") else 0,
                1 if event.get("tz_assumed") else 0,
                event.get("device") or "desconocido",
                event.get("vendor") or "unknown",
                event.get("severity_original") or "",
                event.get("severity_num"),
                event.get("mnemonic"),
                event.get("message") or "",
                event.get("raw") or "",
                json.dumps(event.get("fields") or {}, ensure_ascii=False),
                event.get("source") or "file",
                event.get("source_name") or "",
                1 if event.get("unparsed") else 0,
                event.get("criticality") or "informativo",
                event.get("title") or "Evento",
                event.get("explanation") or "",
                event.get("probable_cause") or "",
                json.dumps(event.get("actions") or [], ensure_ascii=False),
                event.get("signature_id"),
                now,
            )
        )
    with _LOCK:
        conn = connect()
        conn.executemany(
            """
            INSERT INTO events (
                timestamp, timestamp_estimated, tz_assumed, device, vendor, severity_original,
                severity_num, mnemonic, message, raw, fields_json, source, source_name, unparsed,
                criticality, title, explanation, probable_cause, actions_json, signature_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
    return len(rows)


def _like(text):
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "%" + escaped + "%"


def _filters(criticality, vendor, device, q, start, end):
    clauses = []
    params = []
    if criticality:
        clauses.append("criticality = ?")
        params.append(criticality)
    if vendor:
        clauses.append("vendor = ?")
        params.append(vendor)
    if device:
        clauses.append("device = ?")
        params.append(device)
    if start:
        clauses.append("timestamp >= ?")
        params.append(start)
    if end:
        clauses.append("timestamp <= ?")
        params.append(end)
    if q:
        pattern = _like(q)
        clauses.append(
            "(message LIKE ? ESCAPE '\\' OR raw LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\' "
            "OR IFNULL(mnemonic, '') LIKE ? ESCAPE '\\' OR device LIKE ? ESCAPE '\\')"
        )
        params.extend([pattern, pattern, pattern, pattern, pattern])
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def list_events(criticality=None, vendor=None, device=None, q=None, start=None, end=None, order="desc", limit=200, offset=0):
    where, params = _filters(criticality, vendor, device, q, start, end)
    direction = "ASC" if order == "asc" else "DESC"
    query = "SELECT * FROM events %s ORDER BY timestamp %s, id %s LIMIT ? OFFSET ?" % (where, direction, direction)
    count_query = "SELECT COUNT(*) AS total FROM events %s" % where
    with _LOCK:
        conn = connect()
        total = conn.execute(count_query, params).fetchone()["total"]
        rows = conn.execute(query, params + [limit, offset]).fetchall()
    return [dict(row) for row in rows], total


def summary(criticality=None, vendor=None, device=None, q=None, start=None, end=None):
    where, params = _filters(criticality, vendor, device, q, start, end)
    query = "SELECT criticality, COUNT(*) AS total FROM events %s GROUP BY criticality" % where
    with _LOCK:
        conn = connect()
        rows = conn.execute(query, params).fetchall()
        total = conn.execute("SELECT COUNT(*) AS total FROM events %s" % where, params).fetchone()["total"]
    counts = {row["criticality"]: row["total"] for row in rows}
    return {"total": total, "by_criticality": counts}


def list_devices():
    with _LOCK:
        conn = connect()
        rows = conn.execute("SELECT DISTINCT device FROM events ORDER BY device COLLATE NOCASE").fetchall()
    return [row["device"] for row in rows]


def get_event(event_id):
    with _LOCK:
        conn = connect()
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    return dict(row) if row else None


def save_llm(event_id, explanation, probable_cause, actions):
    with _LOCK:
        conn = connect()
        conn.execute(
            """
            UPDATE events
            SET llm_explanation = ?, llm_probable_cause = ?, llm_actions_json = ?, llm_enhanced = 1, llm_error = NULL
            WHERE id = ?
            """,
            (explanation, probable_cause, json.dumps(actions, ensure_ascii=False), event_id),
        )
        conn.commit()


def save_llm_error(event_id, error):
    with _LOCK:
        conn = connect()
        conn.execute("UPDATE events SET llm_error = ? WHERE id = ?", (error, event_id))
        conn.commit()


def purge():
    with _LOCK:
        conn = connect()
        conn.execute("DELETE FROM events")
        conn.commit()
        conn.execute("VACUUM")
