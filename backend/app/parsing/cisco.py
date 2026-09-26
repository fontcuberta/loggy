import re
from datetime import datetime

from app.analysis.criticality import SEVERITY_NAMES
from app.parsing.timeutil import MONTHS, infer_year, parse_tz_token, to_utc

MONTH = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"

CISCO_RE = re.compile(
    r"%(?P<fac>[A-Z][A-Z0-9_]*)-(?P<sev>[0-7])-(?P<mnem>[A-Z0-9_]+):\s*(?P<msg>.*)$"
)
CISCO_TS = re.compile(
    r"^(?:(?P<seq>\d+):\s+)?(?P<unsync>[*.])?(?P<mon>" + MONTH + r")\s+"
    r"(?P<day>\d{1,2})\s+(?:(?P<year>\d{4})\s+)?(?P<hms>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<ms>\d+))?\s*(?P<rest>.*)$"
)
USER_BY = re.compile(r"\bby ([A-Za-z0-9._$@\\-]+)")
USER_NAME = re.compile(r"Username = ([^,;\s]+)")
USER_ANGLE = re.compile(r"User <([^>]+)>")
INTERFACE = re.compile(r"Interface ([A-Za-z][\w/.:-]*)")


def is_cisco(text):
    return CISCO_RE.search(text or "") is not None


def _split_rest(rest):
    rest = (rest or "").strip()
    if rest.startswith(":"):
        rest = rest[1:].strip()
    if not rest:
        return None, None
    token, _, tail = rest.partition(" ")
    token_clean = token.rstrip(":")
    tzinfo = parse_tz_token(token_clean)
    if tzinfo is not None:
        host = tail.strip().rstrip(":").strip() or None
        return tzinfo, host
    host = rest.rstrip(":").strip() or None
    return None, host


def parse_cisco_timestamp(prefix, now, default_tz):
    match = CISCO_TS.match(prefix.strip())
    if not match:
        return None
    try:
        month = MONTHS[match.group("mon")]
        day = int(match.group("day"))
        hour, minute, second = [int(part) for part in match.group("hms").split(":")]
        frac = match.group("ms") or ""
        micro = int((frac + "000000")[:6]) if frac else 0
        year_text = match.group("year")
        year = int(year_text) if year_text else infer_year(month, day, now, default_tz)
        naive = datetime(year, month, day, hour, minute, second, micro)
    except (KeyError, ValueError):
        return None
    tzinfo, host = _split_rest(match.group("rest"))
    if tzinfo is None:
        aware = to_utc(naive, default_tz)
        tz_assumed = True
    else:
        aware = to_utc(naive, tzinfo)
        tz_assumed = False
    estimated = year_text is None or bool(match.group("unsync"))
    return {
        "dt": aware,
        "estimated": estimated,
        "tz_assumed": tz_assumed,
        "host": host,
        "rank": 0,
    }


def _extract_fields(message):
    fields = {}
    user = USER_NAME.search(message) or USER_ANGLE.search(message) or USER_BY.search(message)
    if user:
        fields["user"] = user.group(1)
    interface = INTERFACE.search(message)
    if interface:
        fields["interface"] = interface.group(1)
    return fields


def parse_cisco_body(body):
    match = CISCO_RE.search(body)
    if not match:
        return None
    prefix = body[: match.start()]
    severity = int(match.group("sev"))
    code = "%s-%s-%s" % (match.group("fac"), match.group("sev"), match.group("mnem"))
    message = match.group("msg").strip()
    return {
        "prefix": prefix,
        "severity": severity,
        "code": code,
        "message": message,
        "facility": match.group("fac"),
        "mnemonic_short": match.group("mnem"),
    }
