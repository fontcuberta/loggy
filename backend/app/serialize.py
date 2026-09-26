import json

from app.analysis.criticality import label


def _loads(value, fallback):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def event_view(row, engine, include_raw=False):
    actions = _loads(row.get("actions_json"), [])
    llm_actions = _loads(row.get("llm_actions_json"), None)
    explanation = row.get("explanation") or ""
    cause = row.get("probable_cause") or ""
    engine_used = "rules"
    enhanced = bool(row.get("llm_enhanced")) and bool(row.get("llm_explanation"))
    if engine in ("llm", "hybrid") and enhanced:
        explanation = row.get("llm_explanation") or explanation
        cause = row.get("llm_probable_cause") or cause
        if llm_actions:
            actions = llm_actions
        engine_used = engine
    payload = {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "timestamp_estimated": bool(row["timestamp_estimated"]),
        "tz_assumed": bool(row["tz_assumed"]),
        "device": row["device"],
        "vendor": row["vendor"],
        "severity_original": row.get("severity_original") or "",
        "severity_num": row.get("severity_num"),
        "mnemonic": row.get("mnemonic"),
        "message": row.get("message") or "",
        "source": row.get("source"),
        "source_name": row.get("source_name"),
        "unparsed": bool(row.get("unparsed")),
        "criticality": row.get("criticality"),
        "criticality_label": label(row.get("criticality")),
        "title": row.get("title") or "",
        "explanation": explanation,
        "probable_cause": cause,
        "actions": actions,
        "signature_id": row.get("signature_id"),
        "engine_used": engine_used,
        "llm_enhanced": enhanced,
        "llm_error": row.get("llm_error"),
    }
    if include_raw:
        payload["raw"] = row.get("raw") or ""
        payload["fields"] = _loads(row.get("fields_json"), {})
        payload["rule_explanation"] = row.get("explanation") or ""
        payload["rule_actions"] = _loads(row.get("actions_json"), [])
    return payload
