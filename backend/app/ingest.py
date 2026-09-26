from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from app.analysis.rules import apply_rules
from app.db import get_settings, insert_events
from app.parsing.pipeline import parse_line


def _timezone():
    settings = get_settings()
    try:
        return ZoneInfo(settings["timezone"])
    except Exception:
        return ZoneInfo("UTC")


def build_event(line, source, source_name, default_tz=None, now=None):
    event = parse_line(
        line,
        source=source,
        source_name=source_name,
        now=now or datetime.now(timezone.utc),
        default_tz=default_tz or _timezone(),
    )
    if event is None:
        return None
    return apply_rules(event)


def ingest_lines(lines, source, source_name):
    default_tz = _timezone()
    now = datetime.now(timezone.utc)
    batch = []
    parsed = 0
    unparsed = 0
    for line in lines:
        if line is None:
            continue
        text = str(line).strip()
        if not text:
            continue
        event = build_event(text, source, source_name, default_tz=default_tz, now=now)
        if event is None:
            continue
        batch.append(event)
        if event.get("unparsed"):
            unparsed += 1
        else:
            parsed += 1
        if len(batch) >= 400:
            insert_events(batch)
            batch = []
    if batch:
        insert_events(batch)
    return {"accepted": parsed + unparsed, "parsed": parsed, "unparsed": unparsed}
