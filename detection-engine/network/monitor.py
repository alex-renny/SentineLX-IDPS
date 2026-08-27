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

from scapy.all import conf, sniff, IP, TCP, UDP, ICMP
from detection.ddos import DDoSDetector
from detection.port_scan import PortScanDetector


# ---------------------------------------------------------
# Port scan detector
# ---------------------------------------------------------

detector = PortScanDetector(
    threshold=30,
    window_seconds=10
)

ddos_detector = DDoSDetector(
    threshold=int(os.getenv("SENTINELX_DDOS_THRESHOLD", "1000")),
    window_seconds=1,
)


# ---------------------------------------------------------
# Capture interface
# ---------------------------------------------------------

def resolve_capture_interface():
    """Return the configured Scapy interface and a dashboard-safe label.

    Set SENTINELX_CAPTURE_INTERFACE to an Npcap interface name when needed.
    Otherwise SENTINELX_CAPTURE_IP selects the interface owning that IPv4
    address. This avoids accidentally falling back to a VPN or virtual NIC.
    """

    configured_interface = os.getenv("SENTINELX_CAPTURE_INTERFACE")

    if configured_interface:
        return configured_interface, configured_interface

    capture_ip = os.getenv("SENTINELX_CAPTURE_IP")

    if capture_ip:
        for interface in conf.ifaces.values():
            if getattr(interface, "ip", None) == capture_ip:
                return interface.network_name, interface.name

        raise RuntimeError(
            f"No Scapy interface owns SENTINELX_CAPTURE_IP={capture_ip}"
        )

    return conf.iface, str(conf.iface)


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
    tcp_flags = None

    if packet.haslayer(TCP):

        protocol = "TCP"

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        tcp_flags = int(packet[TCP].flags)

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
        "tcp_flags": tcp_flags,
        "packet_size": len(packet)
    }

    return packet_data


# ---------------------------------------------------------
# Capture traffic
# ---------------------------------------------------------

def capture_traffic(duration=5):

    packets = []
    alerts = []
    capture_interface, interface_label = resolve_capture_interface()

    def packet_handler(packet):

        packet_data = process_packet(packet)

        if not packet_data:
            return

        packets.append(packet_data)

        for active_detector in (detector, ddos_detector):
            alert = active_detector.process_packet(packet_data)

            if alert:
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
        timeout=duration,
        iface=capture_interface,
    )

    return packets, alerts, interface_label


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    start_time = time.time()

    packets, alerts, capture_interface = capture_traffic(5)

    result = {
        "success": True,
        "timestamp": datetime.now().isoformat(),
        "duration": round(
            time.time() - start_time,
            2
        ),
        "capture_interface": capture_interface,
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
