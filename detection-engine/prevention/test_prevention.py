import os
import sys
from unittest.mock import patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from prevention.prevention_engine import PreventionEngine


def main():

    os.environ["SENTINELX_PREVENTION_MODE"] = "test"
    os.environ["SENTINELX_PREVENTION_AUTO_BLOCK"] = "false"
    engine = PreventionEngine()

    test_ip = "192.168.1.100"

    print("\n================================")
    print(" SentinelX Prevention Test")
    print("================================")

    print("\nTesting BLOCK...")

    result = engine.block_ip(
        test_ip,
        reason="Test port scan detection"
    )

    print(result)
    assert result["action"] == "BLOCK_SIMULATED"
    assert result["rule"] == "SentinelX-IDPS-BLOCK-192_168_1_100"
    assert result["success"] is True

    print("\nTesting UNBLOCK...")

    result = engine.unblock_ip(test_ip)

    print(result)
    assert result["action"] == "UNBLOCK_SIMULATED"

    rejected = engine.block_ip("127.0.0.1")
    assert rejected["success"] is False
    assert rejected["action"] == "BLOCK_REJECTED"

    print("\n[PASS] Test-mode prevention checks passed")
    print("Real Windows Firewall rules are only created when")
    print("SENTINELX_PREVENTION_MODE=active")

    os.environ["SENTINELX_PREVENTION_MODE"] = "active"
    os.environ["SENTINELX_PREVENTION_AUTO_BLOCK"] = "false"
    live_engine = PreventionEngine()
    assert live_engine.mode == "active"

    pending = live_engine.block_ip(
        "198.51.100.20",
        reason="Auto detection",
        source="auto",
    )
    assert pending["action"] == "BLOCK_PENDING"
    assert pending["rule"] == "SentinelX-IDPS-BLOCK-198_51_100_20"

    with patch(
        "prevention.prevention_engine.WindowsFirewall.block_ip"
    ) as mock_block:
        mock_block.return_value = {
            "success": True,
            "action": "BLOCKED",
            "ip": "198.51.100.20",
            "rule": "SentinelX-IDPS-BLOCK-198_51_100_20",
        }

        live_result = live_engine.block_ip(
            "198.51.100.20",
            reason="Mocked live block",
            source="manual",
        )

        assert live_result["action"] == "BLOCKED"
        assert live_result["rule"] == "SentinelX-IDPS-BLOCK-198_51_100_20"
        mock_block.assert_called_once()

    print("\n[PASS] Active-mode pending auto-block and manual handoff passed")


if __name__ == "__main__":
    main()
