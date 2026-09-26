import socket
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGGY_DB", str(tmp_path / "loggy.db"))
    monkeypatch.setenv("LOGGY_SYSLOG_PORT", "0")
    from app import db
    from app.main import app

    db.close()
    with TestClient(app) as test_client:
        yield test_client
    db.close()


def _upload(client, name, content):
    return client.post("/api/upload", files={"files": (name, content, "text/plain")})


def test_upload_sorts_filters_and_keeps_unparsed(client):
    content = "\n".join(
        [
            "Sep 23 18:00:00: %SYS-5-CONFIG_I: Configured from console by admin on vty0",
            "Sep 23 18:10:00: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down",
            "esto no es un log",
        ]
    )
    uploaded = _upload(client, "sw.log", content)
    assert uploaded.status_code == 200
    body = uploaded.json()
    assert body["accepted"] == 3
    assert body["parsed"] == 2
    assert body["unparsed"] == 1

    listed = client.get("/api/events").json()
    cisco = [event for event in listed["events"] if event["vendor"] == "cisco"]
    assert listed["total"] == 3
    assert cisco[0]["title"] == "Interfaz caída"
    assert cisco[1]["title"] == "Cambio de configuración"
    assert any(event["unparsed"] for event in listed["events"])

    ascending = client.get("/api/events", params={"order": "asc"}).json()
    cisco_asc = [event for event in ascending["events"] if event["vendor"] == "cisco"]
    assert cisco_asc[0]["signature_id"] == "cisco-config-change"

    altos = client.get("/api/events", params={"criticality": "alto"}).json()
    assert altos["total"] == 1
    found = client.get("/api/events", params={"q": "Gi0/1"}).json()
    assert found["total"] == 1

    link = cisco[0]
    detail = client.get("/api/events/%s" % link["id"], params={"enrich": "false"}).json()
    assert "Gi0/1" in detail["raw"]
    assert detail["criticality"] == "alto"
    assert detail["actions"]
    summary = client.get("/api/summary").json()
    assert summary["total"] == 3
    assert summary["by_criticality"]["alto"] == 1


def test_two_files_keep_their_names_when_there_is_no_hostname(client):
    cisco = "%ASA-6-302013: Built outbound TCP connection\n"
    forti = (
        'date=2024-09-23 time=18:10:01 devname="FGT-HQ" tz="+0200" type="traffic" '
        'subtype="forward" level="warning" action="deny" msg="denied"\n'
    )
    response = client.post(
        "/api/upload",
        files=[
            ("files", ("asa.log", cisco, "text/plain")),
            ("files", ("fgt.log", forti, "text/plain")),
        ],
    )
    assert response.status_code == 200
    events = client.get("/api/events").json()["events"]
    devices = {event["device"] for event in events}
    assert "FGT-HQ" in devices
    assert "asa.log" in devices


def test_settings_reject_remote_models_and_switch_engine(client):
    remote = client.put("/api/settings", json={"ollama_url": "http://example.com:11434"})
    assert remote.status_code == 400
    local = client.put("/api/settings", json={"engine": "rules", "ollama_url": "http://127.0.0.1:11434"})
    assert local.status_code == 200
    assert local.json()["settings"]["engine"] == "rules"
    assert client.get("/api/settings").json()["ollama_url"].startswith("http://127.0.0.1")


def test_purge_removes_events(client):
    _upload(client, "a.log", "linea suelta\n")
    assert client.get("/api/events").json()["total"] == 1
    assert client.post("/api/purge").status_code == 200
    assert client.get("/api/events").json()["total"] == 0


def test_syslog_udp_and_tcp_land_on_the_timeline(client):
    status = client.get("/api/syslog").json()
    assert status["running"] is True
    assert status["host"] == "127.0.0.1"
    port = status["port"]

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.sendto(
        b"%ASA-4-106023: Deny tcp src outside:203.0.113.5/9 dst inside:10.0.0.8/80\n",
        ("127.0.0.1", port),
    )
    udp.close()

    tcp = socket.create_connection(("127.0.0.1", port), timeout=2)
    tcp.sendall(
        b'<189>date=2024-09-23 time=18:10:01 devname="FGT-EDGE" tz="+0200" type="utm" '
        b'subtype="virus" level="alert" action="blocked" msg="malware"\n'
    )
    tcp.close()

    events = []
    for _ in range(40):
        payload = client.get("/api/events").json()
        events = payload["events"]
        if payload["total"] >= 2:
            break
        time.sleep(0.05)
    vendors = {event["vendor"] for event in events}
    assert "cisco" in vendors
    assert "fortigate" in vendors
    assert any(event["device"] == "FGT-EDGE" and event["criticality"] == "critico" for event in events)
