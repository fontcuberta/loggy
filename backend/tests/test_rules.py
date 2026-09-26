from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from app.analysis.criticality import raise_floor
from app.analysis.llm import assert_local_url, combine, parse_llm_payload
from app.analysis.llm import LocalModelError
from app.analysis.rules import apply_rules
from app.parsing.pipeline import parse_line
from app.serialize import event_view

NOW = datetime(2024, 9, 23, 12, 0, tzinfo=timezone.utc)
MADRID = ZoneInfo("Europe/Madrid")


def parse(line):
    event = parse_line(line, source="file", source_name="fw.log", now=NOW, default_tz=MADRID)
    return apply_rules(event)


def test_signature_catalogue_covers_the_planned_cases():
    link = parse("Sep 23 18:10:01: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down")
    config = parse("Sep 23 18:10:02 CORE %SYS-5-CONFIG_I: Configured from console by admin on vty0")
    login = parse("%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: root] [Source: 203.0.113.4]")
    deny = parse("%ASA-4-106023: Deny tcp src outside:203.0.113.5/1 dst inside:10.0.0.8/80")
    built = parse("%ASA-6-302013: Built outbound TCP connection")
    ips = parse(
        'date=2024-09-23 time=18:10:01 devname="FGT-HQ" tz="+0200" type="utm" subtype="ips" '
        'level="warning" action="detected" msg="IPS signature detected"'
    )
    blocked = parse(
        'date=2024-09-23 time=18:10:02 devname="FGT-HQ" tz="+0200" type="utm" subtype="ips" '
        'level="warning" action="dropped" msg="IPS blocked"'
    )
    virus = parse(
        'date=2024-09-23 time=18:10:03 devname="FGT-HQ" tz="+0200" type="utm" subtype="virus" '
        'level="notice" action="blocked" msg="malware"'
    )
    traffic = parse(
        'date=2024-09-23 time=18:00:00 devname="FGT-HQ" tz="+0200" type="traffic" subtype="forward" '
        'level="notice" action="accept" msg="ok"'
    )
    failed = parse(
        'date=2024-09-23 time=18:05:00 devname="FGT-HQ" tz="+0200" type="event" subtype="system" '
        'level="warning" msg="Administrator admin login failed from 198.51.100.4"'
    )
    assert link["title"] == "Interfaz caída"
    assert link["criticality"] == "alto"
    assert config["criticality"] == "medio"
    assert config["signature_id"] == "cisco-config-change"
    assert login["criticality"] == "alto"
    assert deny["title"] == "Tráfico denegado por política"
    assert built["criticality"] == "informativo"
    assert ips["criticality"] == "critico"
    assert ips["title"] == "Intrusión detectada sin bloqueo"
    assert blocked["criticality"] == "alto"
    assert virus["criticality"] == "critico"
    assert traffic["criticality"] == "bajo"
    assert failed["criticality"] == "alto"
    assert failed["title"] == "Inicio de sesión fallido"
    assert link["actions"]


def test_floor_never_lowers_severity():
    assert raise_floor("critico", "bajo") == "critico"
    assert raise_floor("bajo", "alto") == "alto"


def test_unparsed_keeps_pri_criticality():
    event = parse("<26>garbage from another vendor")
    assert event["unparsed"] is True
    assert event["title"] == "Línea no reconocida"
    assert event["criticality"] == "critico"


def test_local_model_url_rejects_remote_hosts():
    assert assert_local_url("http://127.0.0.1:11434") == "http://127.0.0.1:11434"
    assert assert_local_url("http://localhost:11434/") == "http://localhost:11434"
    try:
        assert_local_url("https://example.com/api")
    except LocalModelError:
        pass
    else:
        raise AssertionError("debio rechazar un host remoto")


def test_hybrid_merge_keeps_rule_actions_and_ignores_model_criticality():
    event = {
        "explanation": "Regla base",
        "probable_cause": "Causa base",
        "actions": ["Comprueba la interfaz"],
        "criticality": "critico",
    }
    payload = parse_llm_payload(
        '{"criticality":"informativo","explanation":"Texto ampliado","probable_cause":"Causa ampliada","actions":["Comprueba la interfaz","Mira el vecino"]}'
    )
    explanation, cause, actions = combine(event, payload, "hybrid")
    assert explanation == "Texto ampliado"
    assert cause == "Causa ampliada"
    assert actions == ["Comprueba la interfaz", "Mira el vecino"]
    assert "criticality" not in payload or event["criticality"] == "critico"


def test_serialize_does_not_let_the_model_replace_criticality():
    row = {
        "id": 1,
        "timestamp": "2024-09-23T16:10:01.000+00:00",
        "timestamp_estimated": 1,
        "tz_assumed": 1,
        "device": "r1",
        "vendor": "cisco",
        "severity_original": "2 critical",
        "severity_num": 2,
        "mnemonic": "SYS-2-MALLOCFAIL",
        "message": "fallo",
        "raw": "raw",
        "fields_json": "{}",
        "source": "file",
        "source_name": "a.log",
        "unparsed": 0,
        "criticality": "critico",
        "title": "Sin memoria en el equipo",
        "explanation": "regla",
        "probable_cause": "causa",
        "actions_json": '["Revisa la memoria"]',
        "signature_id": "cisco-memory",
        "llm_explanation": "el modelo lo ve leve",
        "llm_probable_cause": "nada",
        "llm_actions_json": '["Ignoralo"]',
        "llm_enhanced": 1,
        "llm_error": None,
    }
    view = event_view(row, "llm", include_raw=True)
    assert view["criticality"] == "critico"
    assert view["criticality_label"] == "Crítico"
    assert view["explanation"] == "el modelo lo ve leve"
    rules = event_view(row, "rules")
    assert rules["explanation"] == "regla"
    assert rules["actions"] == ["Revisa la memoria"]
