import os
import sys

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from detection.port_scan import PortScanDetector
from services.alert_manager import AlertManager


def main():

    detector = PortScanDetector(
        threshold=30,
        window_seconds=10
    )

    alert_manager = AlertManager()

    print("\n========================================")
    print(" SentinelX Port Scan Pipeline Test")
    print("========================================\n")

    detected = None

    # Simulate 30 unique ports from one source IP
    for port in range(1, 31):

        packet = {
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.10",
            "destination_port": port,
            "protocol": "TCP"
        }

        alert = detector.process_packet(packet)

        if alert:
            detected = alert
            break

    # --------------------------------------------------------
    # Verify detection
    # --------------------------------------------------------

    if not detected:

        print("❌ Port scan was NOT detected")
        return

    print("🚨 Raw detector alert:")
    print(detected)

    # --------------------------------------------------------
    # Process through AlertManager
    # --------------------------------------------------------

    processed = alert_manager.process_alert(
        detected
    )

    if not processed:

        print("❌ AlertManager returned no processed alert")
        return

    print("\n🛡️ Processed alert:")
    print(processed)

    # --------------------------------------------------------
    # Pipeline result
    # --------------------------------------------------------

    print("\n========================================")
    print(" Pipeline Result")
    print("========================================")

    print(
        "Detection:",
        processed["type"]
    )

    print(
        "Severity:",
        processed["severity"]
    )

    print(
        "Source IP:",
        processed["source_ip"]
    )

    print(
        "Ports:",
        processed["ports_detected"]
    )

    print(
        "Prevention:",
        processed["prevention"]["action"]
    )

    print(
        "Mode:",
        processed["prevention"]["mode"]
    )

    print("\n✅ Pipeline test completed")


if __name__ == "__main__":
    main()