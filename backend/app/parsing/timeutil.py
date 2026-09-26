import re
from datetime import datetime, timedelta, timezone

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

ABBR_OFFSET_HOURS = {
    "UTC": 0,
    "GMT": 0,
    "Z": 0,
    "WET": 0,
    "WEST": 1,
    "CET": 1,
    "CEST": 2,
    "EST": -5,
    "EDT": -4,
    "CST": -6,
    "CDT": -5,
    "MST": -7,
    "MDT": -6,
    "PST": -8,
    "PDT": -7,
}


def infer_year(month, day, now, default_tz):
    local_today = now.astimezone(default_tz).date()
    year = local_today.year
    try:
        candidate = datetime(year, month, day).date()
    except ValueError:
        return year - 1
    if candidate > local_today + timedelta(days=1):
        return year - 1
    return year


def parse_tz_token(token):
    if not token:
        return None
    token = token.strip().strip('"').strip("'")
    if token in ABBR_OFFSET_HOURS:
        return timezone(timedelta(hours=ABBR_OFFSET_HOURS[token]))
    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", token)
    if not match:
        return None
    sign = 1 if match.group(1) == "+" else -1
    return timezone(timedelta(hours=sign * int(match.group(2)), minutes=sign * int(match.group(3))))


def parse_epoch(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if number > 10 ** 16:
        seconds = number / 1e9
    elif number > 10 ** 13:
        seconds = number / 1e6
    elif number > 10 ** 11:
        seconds = number / 1e3
    else:
        seconds = number
    try:
        return datetime.fromtimestamp(seconds, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def to_utc(naive, tzinfo):
    return naive.replace(tzinfo=tzinfo).astimezone(timezone.utc)


def isoformat_utc(value):
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds")
