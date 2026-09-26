import re
from datetime import datetime

from app.parsing.timeutil import MONTHS, infer_year, to_utc

MONTH = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"

RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d+)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+(?P<proc>\S+)\s+(?P<msgid>\S+)\s+(?:-\s+)?(?P<msg>.*)$"
)
RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<mon>" + MONTH + r")\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s?(?P<msg>.*)$"
)
PRI_ONLY = re.compile(r"^<(?P<pri>\d{1,3})>(?P<msg>.*)$", re.DOTALL)


def _valid_pri(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if 0 <= number <= 191:
        return number
    return None


def _nil(value):
    if value in (None, "", "-"):
        return None
    return value


def _parse_rfc5424_ts(value):
    if not value or value == "-":
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def _parse_rfc3164_ts(match, now, default_tz):
    try:
        month = MONTHS[match.group("mon")]
        day = int(match.group("day"))
        hour, minute, second = [int(part) for part in match.group("time").split(":")]
        year = infer_year(month, day, now, default_tz)
        naive = datetime(year, month, day, hour, minute, second)
    except (KeyError, ValueError):
        return None
    return to_utc(naive, default_tz)


def parse_header(text, now, default_tz):
    result = {
        "pri": None,
        "host": None,
        "body": text,
        "timestamp": None,
        "timestamp_estimated": False,
        "tz_assumed": False,
    }
    match = RFC5424.match(text)
    if match and _valid_pri(match.group("pri")) is not None:
        pri = _valid_pri(match.group("pri"))
        stamp = _parse_rfc5424_ts(match.group("ts"))
        result.update(
            {
                "pri": pri,
                "host": _nil(match.group("host")),
                "body": match.group("msg"),
                "timestamp": stamp,
                "timestamp_estimated": False,
                "tz_assumed": False,
            }
        )
        return result

    match = RFC3164.match(text)
    if match and _valid_pri(match.group("pri")) is not None:
        result.update(
            {
                "pri": _valid_pri(match.group("pri")),
                "host": _nil(match.group("host")),
                "body": match.group("msg"),
                "timestamp": _parse_rfc3164_ts(match, now, default_tz),
                "timestamp_estimated": True,
                "tz_assumed": True,
            }
        )
        return result

    match = PRI_ONLY.match(text)
    if match and _valid_pri(match.group("pri")) is not None:
        result["pri"] = _valid_pri(match.group("pri"))
        result["body"] = match.group("msg").strip()
    return result


def pri_severity(pri):
    if pri is None:
        return None
    return pri % 8
