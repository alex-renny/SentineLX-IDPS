"""Focused checks for the Phase 2 detector contracts."""

import json
import os
import sys
import tempfile
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scapy.all import conf

from detection.brute_force import BruteForceDetector
from detection.ddos import DDoSDetector
from network.monitor import resolve_capture_interface
from services.auth_event_reader import AuthEventReader
from services.alert_manager import AlertManager


def auth_event(service, attempt):
    return {
        "event_type": "AUTH_FAILURE",
        "source_ip": "198.51.100.25",
        "target": "sentinelx-test",
        "service": service,
        "timestamp": datetime.now().isoformat(),
        "attempt": attempt,
    }


def test_auth_event_reader():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as stream:
        path = stream.name
        for service in ("SSH", "FTP", "HTTP", "RDP"):
            stream.write(json.dumps(auth_event(service, 1)) + "\n")
        stream.write(json.dumps({"event_type": "AUTH_FAILURE", "service": "SMTP"}) + "\n")

    try:
        events = AuthEventReader(path).read_events()
        assert [event["service"] for event in events] == ["SSH", "FTP", "HTTP", "RDP"]
    finally:
        os.unlink(path)


def test_brute_force():
    detector = BruteForceDetector(threshold=20, window_seconds=60)
    alert = None

    for attempt in range(20):
        alert = detector.process_event(auth_event("SSH", attempt))

    assert alert and alert["type"] == "BRUTE_FORCE"
    assert alert["severity"] == "HIGH"
    assert alert["attempts"] == 20

    processed = AlertManager().process_alert(alert)
    assert processed and processed["prevention"]
    assert processed["prevention"]["action"] == "BLOCK_SIMULATED"
    assert processed["status"] == "DETECTED"
    assert processed["timeline"][0]["status"] == "DETECTED"


def test_ddos():
    detector = DDoSDetector(threshold=1000, window_seconds=1)
    alert = None
    timestamp = datetime.now().isoformat()

    for number in range(1000):
        alert = detector.process_packet({
            "source_ip": "198.51.100.30",
            "destination_ip": "192.0.2.10",
            "protocol": "UDP",
            "destination_port": 443,
            "timestamp": timestamp,
            "packet_number": number,
        })

    assert alert and alert["type"] == "DDOS"
    assert alert["severity"] == "CRITICAL"
    assert alert["packets_per_second"] == 1000


def test_resolve_capture_interface_falls_back_for_unknown_ip(monkeypatch):
    monkeypatch.delenv("SENTINELX_CAPTURE_INTERFACE", raising=False)
    monkeypatch.setenv("SENTINELX_CAPTURE_IP", "192.168.255.255")

    interface_name, label = resolve_capture_interface()

    assert interface_name
    assert label
    assert interface_name in (str(conf.iface), getattr(conf.iface, "name", str(conf.iface)))


if __name__ == "__main__":
    test_auth_event_reader()
    test_brute_force()
    test_ddos()
    test_resolve_capture_interface_falls_back_for_unknown_ip()
    print("Phase 2 brute-force and DDoS pipeline: PASS")
