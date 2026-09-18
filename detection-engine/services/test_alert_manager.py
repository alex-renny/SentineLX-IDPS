import os
import sys
from unittest.mock import patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from services.alert_manager import AlertManager
from prevention.prevention_engine import PreventionEngine


def test_detect_then_pending_in_active_mode(monkeypatch):
    monkeypatch.setenv("SENTINELX_PREVENTION_MODE", "active")
    monkeypatch.setenv("SENTINELX_PREVENTION_AUTO_BLOCK", "false")

    manager = AlertManager(PreventionEngine())
    result = manager.process_alert({
        "type": "PORT_SCAN",
        "severity": "HIGH",
        "source_ip": "192.168.1.100",
        "ports_detected": 30,
        "window_seconds": 10,
        "message": "Possible port scan detected",
    })

    assert result["status"] == "DETECTED"
    assert result["prevention"]["action"] == "BLOCK_PENDING"
    assert result["timeline"][0]["status"] == "DETECTED"


def test_auto_block_sets_blocked_status(monkeypatch):
    monkeypatch.setenv("SENTINELX_PREVENTION_MODE", "active")
    monkeypatch.setenv("SENTINELX_PREVENTION_AUTO_BLOCK", "true")

    engine = PreventionEngine()

    with patch.object(engine, "block_ip") as mock_block:
        mock_block.return_value = {
            "success": True,
            "action": "BLOCKED",
            "ip": "192.168.1.100",
            "rule": "SentinelX-IDPS-BLOCK-192_168_1_100",
        }
        result = AlertManager(engine).process_alert({
            "type": "DDOS",
            "severity": "CRITICAL",
            "source_ip": "192.168.1.100",
            "message": "Traffic flood",
        })

    assert result["status"] == "BLOCKED"
    assert result["timeline"][-1]["status"] == "BLOCKED"
    mock_block.assert_called_once()
    assert mock_block.call_args.kwargs["source"] == "auto"


def main():
    class FakeMonkeypatch:
        def setenv(self, key, value):
            import os
            os.environ[key] = value

    test_detect_then_pending_in_active_mode(FakeMonkeypatch())
    test_auto_block_sets_blocked_status(FakeMonkeypatch())
    print("Alert manager lifecycle: PASS")


if __name__ == "__main__":
    main()
