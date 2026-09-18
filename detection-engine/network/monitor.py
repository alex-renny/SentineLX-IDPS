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
    threshold=int(os.getenv("SENTINELX_PORT_SCAN_THRESHOLD", "30")),
    window_seconds=int(os.getenv("SENTINELX_PORT_SCAN_WINDOW", "10"))
)

ddos_detector = DDoSDetector(
    threshold=int(os.getenv("SENTINELX_DDOS_THRESHOLD", "1000")),
    window_seconds=1,
    ddos_peak_threshold=int(os.getenv("SENTINELX_DDOS_PEAK_THRESHOLD", "3000")),
    sustained_threshold=int(os.getenv("SENTINELX_DDOS_SUSTAINED_THRESHOLD", "1500")),
    sustained_window_seconds=int(os.getenv("SENTINELX_DDOS_SUSTAINED_WINDOW", "5")),
    alert_cooldown_seconds=int(os.getenv("SENTINELX_DDOS_ALERT_COOLDOWN", "30")),
)


# ---------------------------------------------------------
# Capture interface
# ---------------------------------------------------------

def resolve_capture_interface():
    """Return the configured Scapy interface and a dashboard-safe label.

    Set SENTINELX_CAPTURE_INTERFACE to a known adapter name when needed.
    Otherwise SENTINELX_CAPTURE_IP selects the interface owning that IPv4
    address, but if the IP is stale or unavailable we fall back to the first
    active local interface instead of crashing the engine.
    """

    configured_interface = os.getenv("SENTINELX_CAPTURE_INTERFACE")

    if configured_interface:
        configured = conf.ifaces.get(configured_interface)
        return (
            configured_interface,
            configured_interface,
            getattr(configured, "ip", None),
        )

    capture_ip = os.getenv("SENTINELX_CAPTURE_IP")
    default_iface = getattr(conf.iface, "name", str(conf.iface))

    if capture_ip:
        for interface in conf.ifaces.values():
            interface_ip = getattr(interface, "ip", None)
            interface_name = getattr(interface, "name", str(interface))

            if interface_ip == capture_ip:
                return (
                    getattr(interface, "network_name", interface_name),
                    interface_name,
                    interface_ip,
                )

        for interface in conf.ifaces.values():
            interface_ip = getattr(interface, "ip", None)
            if interface_ip:
                fallback_name = getattr(interface, "name", str(interface))
                print(
                    "[network.monitor] SENTINELX_CAPTURE_IP is unavailable; "
                    f"falling back to {fallback_name} instead of {capture_ip}",
                    file=sys.stderr,
                    flush=True,
                )
                return (
                    getattr(interface, "network_name", fallback_name),
                    fallback_name,
                    interface_ip,
                )

        print(
            "[network.monitor] No usable Scapy interface found for "
            f"SENTINELX_CAPTURE_IP={capture_ip}; using default {default_iface}",
            file=sys.stderr,
            flush=True,
        )

    return default_iface, default_iface, getattr(conf.iface, "ip", None)


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
    capture_interface, interface_label, local_ip = resolve_capture_interface()

    def packet_handler(packet):

        packet_data = process_packet(packet)

        if not packet_data:
            return

        packets.append(packet_data)

        active_detectors = []
        if os.getenv("SENTINELX_PORT_SCAN_ENABLED", "true").lower() == "true":
            active_detectors.append(detector)
        if os.getenv("SENTINELX_DDOS_ENABLED", "true").lower() == "true":
            active_detectors.append(ddos_detector)

        for active_detector in active_detectors:
            alert = active_detector.process_packet(packet_data)

            if alert:
                duplicate = any(
                    existing.get("source_ip") == alert.get("source_ip")
                    and existing.get("type") == alert.get("type")
                    for existing in alerts
                )

                if (alert.get("type") != "ABNORMAL_TRAFFIC" or os.getenv("SENTINELX_ABNORMAL_TRAFFIC_ENABLED", "true").lower() == "true") and not duplicate:
                    alerts.append(alert)

    sniff(
        prn=packet_handler,
        store=False,
        timeout=duration,
        iface=capture_interface,
    )

    return packets, alerts, interface_label, local_ip


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    start_time = time.time()

    packets, alerts, capture_interface, local_ip = capture_traffic(5)

    result = {
        "success": True,
        "timestamp": datetime.now().isoformat(),
        "duration": round(
            time.time() - start_time,
            2
        ),
        "capture_interface": capture_interface,
        "local_ip": local_ip,
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
