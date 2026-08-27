from collections import defaultdict
from datetime import datetime, timedelta


class PortScanDetector:
    """
    Detect possible port scanning.

    Default rule:
    30 or more unique destination ports
    from the same source IP within 10 seconds.
    """

    def __init__(self, threshold=30, window_seconds=10):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.activity = defaultdict(list)
        self.last_alert_at = {}

    def process_packet(self, packet):
        source_ip = packet.get("source_ip")
        destination_port = packet.get("destination_port")
        protocol = packet.get("protocol")
        tcp_flags = packet.get("tcp_flags")

        # Ignore packets without an IP or destination port.
        if not source_ip:
            return None

        if destination_port is None:
            return None

        # Port scanning detection only considers TCP and UDP.
        if protocol not in ("TCP", "UDP"):
            return None

        # For TCP, only a SYN without ACK is a new connection attempt.
        # Responses and established-session packets must not count as scans.
        if protocol == "TCP" and tcp_flags is not None:
            is_syn = bool(tcp_flags & 0x02)
            is_ack = bool(tcp_flags & 0x10)
            if not is_syn or is_ack:
                return None

        now = datetime.now()

        # Store this connection attempt.
        self.activity[source_ip].append(
            (now, destination_port)
        )

        # Remove activity older than our detection window.
        cutoff = now - self.window

        self.activity[source_ip] = [
            event
            for event in self.activity[source_ip]
            if event[0] >= cutoff
        ]

        # Count unique destination ports.
        unique_ports = {
            port
            for _, port in self.activity[source_ip]
        }

        # Detect possible port scan.
        if len(unique_ports) >= self.threshold:
            previous_alert = self.last_alert_at.get(source_ip)

            # A single scan produces many packets after reaching the threshold.
            # Emit one alert per source per detection window instead of flooding
            # MongoDB and Socket.IO with duplicates.
            if previous_alert and now - previous_alert < self.window:
                return None

            self.last_alert_at[source_ip] = now

            return {
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "source_ip": source_ip,
                "ports_detected": len(unique_ports),
                "window_seconds": int(
                    self.window.total_seconds()
                ),
                "timestamp": now.isoformat(),
                "message": (
                    f"Possible port scanning detected from "
                    f"{source_ip}: "
                    f"{len(unique_ports)} unique ports "
                    f"within "
                    f"{int(self.window.total_seconds())} seconds"
                ),
            }

        return None


# ---------------------------------------------------------
# TEST MODE
# ---------------------------------------------------------

if __name__ == "__main__":
    detector = PortScanDetector(
        threshold=30,
        window_seconds=10
    )

    alert = None

    # Simulate 30 different destination ports.
    for port in range(1, 31):
        packet = {
            "source_ip": "192.168.1.100",
            "destination_port": port,
            "protocol": "TCP"
        }

        alert = detector.process_packet(packet)

    if alert:
        print("PORT SCAN DETECTED")
        print(alert)
    else:
        print("No scan detected")
