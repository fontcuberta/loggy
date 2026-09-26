from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from app.analysis.rules import apply_rules
from app.parsing.pipeline import parse_line
from app.syslog_server import split_syslog_buffer

NOW = datetime(2024, 9, 23, 12, 0, tzinfo=timezone.utc)
MADRID = ZoneInfo("Europe/Madrid")


def _parse(line, source="file", source_name="equipo.log"):
    return parse_line(line, source=source, source_name=source_name, now=NOW, default_tz=MADRID)


def test_cisco_link_down_uses_message_severity_and_assumed_timezone():
    event = _parse("Sep 23 18:10:01.123: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down")
    assert event["vendor"] == "cisco"
    assert event["mnemonic"] == "LINK-3-UPDOWN"
    assert event["severity_num"] == 3
    assert event["fields"]["interface"] == "GigabitEthernet0/1"
    assert event["timestamp"].hour == 16
    assert event["timestamp"].minute == 10
    assert event["timestamp_estimated"] is True
    assert event["tz_assumed"] is True
    assert event["unparsed"] is False


def test_cisco_message_severity_wins_over_syslog_pri():
    event = _parse("<134>Sep 23 18:10:01 router %SYS-2-MALLOCFAIL: Memory allocation failed")
    assert event["device"] == "router"
    assert event["severity_num"] == 2
    assert event["mnemonic"] == "SYS-2-MALLOCFAIL"
    assert event["fields"]["pri"] == 134


def test_cisco_hostname_before_mnemonic():
    event = _parse("Sep 23 18:10:01 CORE-SW1 %SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.1.1.5)")
    assert event["device"] == "CORE-SW1"
    assert event["fields"]["user"] == "admin"
    assert event["mnemonic"] == "SYS-5-CONFIG_I"


def test_cisco_year_rolls_back_when_the_date_is_ahead():
    event = parse_line(
        "Dec 31 23:59:00: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down",
        source="file",
        source_name="sw.log",
        now=datetime(2025, 1, 2, tzinfo=timezone.utc),
        default_tz=timezone.utc,
    )
    assert event["timestamp"].year == 2024


def test_asa_deny_and_vpn():
    deny = _parse(
        '%ASA-4-106023: Deny tcp src outside:203.0.113.5/51515 dst inside:10.0.0.8/443 by access-group "outside_in"'
    )
    vpn = _parse("%ASA-4-113019: Group = vpn, Username = ana, IP = 203.0.113.9, Session disconnected.")
    assert deny["mnemonic"] == "ASA-4-106023"
    assert deny["severity_num"] == 4
    assert vpn["mnemonic"] == "ASA-4-113019"
    assert vpn["fields"]["user"] == "ana"


def test_fortigate_keeps_device_time_and_quotes():
    event = _parse(
        'date=2024-09-23 time=18:10:01 devname="FGT-HQ" devid="FGT60" tz="+0200" '
        'logid="0419016384" type="utm" subtype="ips" level="alert" srcip=203.0.113.9 '
        'dstip=10.0.0.8 action="detected" msg="IPS signature detected"'
    )
    assert event["vendor"] == "fortigate"
    assert event["device"] == "FGT-HQ"
    assert event["fields"]["srcip"] == "203.0.113.9"
    assert event["fields"]["msg"] == "IPS signature detected"
    assert event["severity_num"] == 1
    assert event["timestamp"].hour == 16
    assert event["timestamp_estimated"] is False
    assert event["tz_assumed"] is False
    assert event["mnemonic"] == "0419016384"


def test_fortigate_after_syslog_header():
    event = _parse(
        '<189>date=2024-09-23 time=18:00:00 devname="FGT-HQ" tz="+0200" type="traffic" '
        'subtype="forward" level="notice" action="accept" msg="ok"'
    )
    assert event["vendor"] == "fortigate"
    assert event["severity_num"] == 5
    assert event["fields"]["pri"] == 189


def test_unknown_line_is_kept_and_uses_pri():
    event = _parse("<26>this is not a known log format")
    assert event["unparsed"] is True
    assert event["vendor"] == "unknown"
    assert event["severity_num"] == 2
    assert "not a known" in event["message"]


def test_rfc5424_timestamp_is_not_estimated():
    event = _parse("<189>1 2024-09-23T16:10:01.000Z fw - - - - %SYS-5-CONFIG_I: Configured from console by admin")
    assert event["vendor"] == "cisco"
    assert event["device"] == "fw"
    assert event["timestamp_estimated"] is False
    assert event["timestamp"].hour == 16


def test_octet_counting_and_plain_newlines():
    message = b"<134>short message!!"
    framed = str(len(message)).encode() + b" " + message
    newline = b"5 denied packets stay intact\n"
    lines, rest = split_syslog_buffer(framed + newline)
    assert lines == ["<134>short message!!", "5 denied packets stay intact"]
    assert rest == b""
    partial, leftover = split_syslog_buffer(b"12 <134>short")
    assert partial == []
    assert leftover.startswith(b"12 ")


def test_rules_raise_floor_without_lowering_link_up():
    down = apply_rules(_parse("Sep 23 18:11:00: %LINEPROTO-5-UPDOWN: Line protocol on Interface Gi0/1, changed state to down"))
    up = apply_rules(_parse("Sep 23 18:12:00: %LINEPROTO-5-UPDOWN: Line protocol on Interface Gi0/1, changed state to up"))
    assert down["criticality"] == "alto"
    assert down["title"] == "Protocolo de línea caído"
    assert up["criticality"] == "bajo"
    assert up["signature_id"] == "cisco-lineproto-up"
