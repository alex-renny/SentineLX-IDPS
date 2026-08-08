import json
import os
import sys
import time
from datetime import datetime

# ---------------------------------------------------------
# Make detection-engine available for imports
# ---------------------------------------------------------

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------
# Imports
# ---------------------------------------------------------

from scapy.all import sniff, IP, TCP, UDP, ICMP
from detection.port_scan import PortScanDetector


# ---------------------------------------------------------
# Port scan detector
# ---------------------------------------------------------

detector = PortScanDetector(
    threshold=30,
    window_seconds=10
)


# ---------------------------------------------------------
# Process packet
# ---------------------------------------------------------

def process_packet(packet):

    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]

    protocol = "OTHER"

    source_port = None
    destination_port = None

    if packet.haslayer(TCP):

        protocol = "TCP"

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):

        protocol = "UDP"

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif packet.haslayer(ICMP):

        protocol = "ICMP"

    packet_data = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": ip_layer.src,
        "destination_ip": ip_layer.dst,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "packet_size": len(packet)
    }

    return packet_data


# ---------------------------------------------------------
# Capture traffic
# ---------------------------------------------------------

def capture_traffic(duration=5):

    packets = []
    alerts = []

    def packet_handler(packet):

        packet_data = process_packet(packet)

        if not packet_data:
            return

        packets.append(packet_data)

        # Send packet to detection engine
        alert = detector.process_packet(packet_data)

        if alert:

            # Prevent duplicate alerts during
            # this capture session.
            duplicate = any(
                existing.get("source_ip") == alert.get("source_ip")
                and existing.get("type") == alert.get("type")
                for existing in alerts
            )

            if not duplicate:
                alerts.append(alert)

    sniff(
        prn=packet_handler,
        store=False,
        timeout=duration
    )

    return packets, alerts


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    start_time = time.time()

    packets, alerts = capture_traffic(5)

    result = {
        "success": True,
        "timestamp": datetime.now().isoformat(),
        "duration": round(
            time.time() - start_time,
            2
        ),
        "packet_count": len(packets),
        "alert_count": len(alerts),
        "packets": packets,
        "alerts": alerts
    }

    # IMPORTANT:
    # stdout contains JSON ONLY.
    print(json.dumps(result))


# ---------------------------------------------------------
# Entry point
# ---------------------------------------------------------

if __name__ == "__main__":
    main()