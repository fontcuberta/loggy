import re
from datetime import datetime

from app.analysis.criticality import FORTIGATE_LEVELS
from app.parsing.timeutil import parse_epoch, parse_tz_token, to_utc

KV = re.compile(r'([A-Za-z_][\w-]*)=(?:"([^"]*)"|([^\s"]+))')


def parse_kv(text):
    fields = {}
    for match in KV.finditer(text or ""):
        if match.group(2) is not None:
            fields[match.group(1)] = match.group(2)
        else:
            fields[match.group(1)] = match.group(3)
    return fields


def is_fortigate(text):
    if not text or "date=" not in text or "time=" not in text:
        return False
    return any(token in text for token in ("type=", "logid=", "devname=", "level=", "devid="))


def parse_fortigate_timestamp(fields, now, default_tz):
    date_text = fields.get("date")
    time_text = fields.get("time")
    if date_text and time_text:
        clock, _, frac = time_text.partition(".")
        try:
            hour, minute, second = [int(part) for part in clock.split(":")]
            year, month, day = [int(part) for part in date_text.split("-")]
            micro = int((frac + "000000")[:6]) if frac else 0
            naive = datetime(year, month, day, hour, minute, second, micro)
        except (TypeError, ValueError):
            naive = None
        if naive is not None:
            tzinfo = parse_tz_token(fields.get("tz"))
            if tzinfo is None and fields.get("tz"):
                tzinfo = _zone(fields.get("tz"))
            if tzinfo is not None:
                return {"dt": to_utc(naive, tzinfo), "estimated": False, "tz_assumed": False, "rank": 0}
            return {
                "dt": to_utc(naive, default_tz),
                "estimated": False,
                "tz_assumed": True,
                "rank": 0,
            }
    epoch = parse_epoch(fields.get("eventtime"))
    if epoch is not None:
        return {"dt": epoch, "estimated": False, "tz_assumed": False, "rank": 0}
    return None


def _zone(name):
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name.strip())
    except Exception:
        return None


def fortigate_severity(fields):
    level = (fields.get("level") or "").strip().lower()
    if level in FORTIGATE_LEVELS:
        return level, FORTIGATE_LEVELS[level]
    return level or None, None
