import os
import sys
from datetime import datetime

# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ============================================================
# IMPORTS
# ============================================================

from detection.port_scan import PortScanDetector
from services.alert_manager import AlertManager


# ============================================================
# CONTROLLED LIVE PIPELINE TEST
# ============================================================

def main():

    print("\n========================================")
    print(" SentinelX Live Pipeline Integration Test")
    print("========================================\n")

    detector = PortScanDetector(
        threshold=30,
        window_seconds=10
    )

    alert_manager = AlertManager()

    detected = None

    # --------------------------------------------------------
    # Simulate packets entering the detection layer
    # --------------------------------------------------------

    print("📡 Feeding controlled test packets...\n")

    for port in range(1, 31):

        packet = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.10",
            "protocol": "TCP",
            "source_port": 50000 + port,
            "destination_port": port,
            "packet_size": 60
        }

        alert = detector.process_packet(packet)

        if alert:
            detected = alert

            print(
                f"🚨 Detection triggered after "
                f"{port} ports"
            )

            break

    # --------------------------------------------------------
    # Detection verification
    # --------------------------------------------------------

    if not detected:

        print("❌ Detection failed")
        return

    print("\n✅ Detection layer working")
    print("----------------------------------------")
    print(f"Type:       {detected['type']}")
    print(f"Severity:   {detected['severity']}")
    print(f"Source IP:  {detected['source_ip']}")
    print(f"Ports:      {detected['ports_detected']}")

    # --------------------------------------------------------
    # Alert Manager
    # --------------------------------------------------------

    print("\n🛡️ Sending alert to AlertManager...")

    processed = alert_manager.process_alert(
        detected
    )

    if not processed:

        print("❌ AlertManager failed")
        return

    print("✅ AlertManager processed alert")

    # --------------------------------------------------------
    # Prevention
    # --------------------------------------------------------

    prevention = processed.get(
        "prevention"
    )

    if not prevention:

        print("❌ Prevention result missing")
        return

    print("\n🛡️ Prevention result")
    print("----------------------------------------")
    print(
        f"Action:     {prevention.get('action', 'UNKNOWN')}"
    )
    print(
        f"Mode:       {prevention.get('mode', 'N/A')}"
    )
    print(
        f"Source IP:  {prevention['ip']}"
    )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    print("\n========================================")
    print(" Integration Test Result")
    print("========================================")

    print("✅ Detection       PASS")
    print("✅ Alert Manager   PASS")
    print("✅ Prevention      PASS")

    print("\n🎉 SentinelX detection pipeline is working.")
    print("========================================\n")


if __name__ == "__main__":
    main()