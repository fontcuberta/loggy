from app.analysis.criticality import SEVERITY_NAMES
from app.parsing.cisco import is_cisco, parse_cisco_body, parse_cisco_timestamp, _extract_fields
from app.parsing.fortigate import fortigate_severity, is_fortigate, parse_fortigate_timestamp, parse_kv
from app.parsing.header import parse_header, pri_severity


def parse_line(raw, source, source_name, now, default_tz):
    text = (raw or "").replace("\x00", "").strip("\ufeff").strip()
    if not text:
        return None
    header = parse_header(text, now, default_tz)
    body = header["body"].strip()
    if _prefer_fortigate(body):
        return _fortigate_event(text, body, header, source, source_name, now, default_tz)
    if is_cisco(body) or is_cisco(text):
        target = body if is_cisco(body) else text
        return _cisco_event(text, target, header, source, source_name, now, default_tz)
    return _unknown_event(text, body, header, source, source_name, now, default_tz)


def _prefer_fortigate(text):
    if not is_fortigate(text):
        return False
    if not is_cisco(text):
        return True
    return text.find("date=") < text.find("%")


def _base_event(raw, source, source_name):
    return {
        "timestamp": None,
        "timestamp_estimated": False,
        "tz_assumed": False,
        "device": "",
        "vendor": "unknown",
        "severity_original": "",
        "severity_num": None,
        "mnemonic": None,
        "message": "",
        "raw": raw[:20000],
        "fields": {},
        "unparsed": False,
        "source": source,
        "source_name": source_name,
    }


def _pick_timestamp(candidates, now):
    usable = [item for item in candidates if item and item.get("dt") is not None]
    if not usable:
        return now, True, True
    usable.sort(key=lambda item: (1 if item.get("estimated") else 0, item.get("rank", 9)))
    best = usable[0]
    return best["dt"], bool(best.get("estimated")), bool(best.get("tz_assumed"))


def _device(*candidates):
    for candidate in candidates:
        if candidate and candidate not in ("-", "localhost"):
            return str(candidate).strip()[:128]
    return "desconocido"


def _header_candidate(header):
    if not header.get("timestamp"):
        return None
    return {
        "dt": header["timestamp"],
        "estimated": header.get("timestamp_estimated", False),
        "tz_assumed": header.get("tz_assumed", False),
        "rank": 1,
    }


def _apply_clock(event, candidates, now):
    stamp, estimated, assumed = _pick_timestamp(candidates, now)
    event["timestamp"] = stamp
    event["timestamp_estimated"] = estimated
    event["tz_assumed"] = assumed


def _cisco_event(raw, body, header, source, source_name, now, default_tz):
    parsed = parse_cisco_body(body)
    event = _base_event(raw, source, source_name)
    if parsed is None:
        return _unknown_event(raw, body, header, source, source_name, now, default_tz)
    clock = parse_cisco_timestamp(parsed["prefix"], now, default_tz)
    fields = _extract_fields(parsed["message"])
    fields.update(
        {
            "facility": parsed["facility"],
            "severity": parsed["severity"],
            "mnemonic": parsed["mnemonic_short"],
            "code": parsed["code"],
        }
    )
    if header.get("pri") is not None:
        fields["pri"] = header["pri"]
    event.update(
        {
            "vendor": "cisco",
            "severity_num": parsed["severity"],
            "severity_original": "%s %s" % (parsed["severity"], SEVERITY_NAMES[parsed["severity"]]),
            "mnemonic": parsed["code"],
            "message": parsed["message"][:8000],
            "fields": fields,
            "device": _device(
                (clock or {}).get("host"),
                header.get("host"),
                source_name if source == "file" else None,
            ),
        }
    )
    _apply_clock(event, [clock, _header_candidate(header)], now)
    return event


def _fortigate_event(raw, body, header, source, source_name, now, default_tz):
    fields = parse_kv(body)
    level, severity_num = fortigate_severity(fields)
    if severity_num is None:
        severity_num = pri_severity(header.get("pri"))
        if severity_num is not None and not level:
            level = SEVERITY_NAMES.get(severity_num, "")
    event = _base_event(raw, source, source_name)
    if header.get("pri") is not None:
        fields["pri"] = header["pri"]
    message = fields.get("msg") or fields.get("logdesc") or body
    logid = fields.get("logid")
    event.update(
        {
            "vendor": "fortigate",
            "severity_num": severity_num,
            "severity_original": level or "",
            "mnemonic": logid,
            "message": message[:8000],
            "fields": fields,
            "device": _device(fields.get("devname"), fields.get("devid"), header.get("host"), source_name if source == "file" else None),
        }
    )
    clock = parse_fortigate_timestamp(fields, now, default_tz)
    _apply_clock(event, [clock, _header_candidate(header)], now)
    return event


def _unknown_event(raw, body, header, source, source_name, now, default_tz):
    event = _base_event(raw, source, source_name)
    severity_num = pri_severity(header.get("pri"))
    fields = {}
    if header.get("pri") is not None:
        fields["pri"] = header["pri"]
    event.update(
        {
            "vendor": "unknown",
            "unparsed": True,
            "severity_num": severity_num,
            "severity_original": SEVERITY_NAMES.get(severity_num, "") if severity_num is not None else "",
            "message": (body or raw)[:8000],
            "fields": fields,
            "device": _device(header.get("host"), source_name if source == "file" else None),
        }
    )
    _apply_clock(event, [_header_candidate(header)], now)
    return event
