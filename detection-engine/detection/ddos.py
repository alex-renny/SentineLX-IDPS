from collections import defaultdict, deque
from datetime import datetime, timedelta


class DDoSDetector:
    """Validate bursts before classifying traffic as a denial-of-service flood."""

    def __init__(
        self,
        threshold=1000,
        window_seconds=1,
        ddos_peak_threshold=None,
        sustained_threshold=None,
        sustained_window_seconds=5,
        alert_cooldown_seconds=30,
    ):
        self.threshold = int(threshold)
        self.window_seconds = int(window_seconds)
        # A one-second burst is telemetry, not automatically a DDoS.
        self.ddos_peak_threshold = int(ddos_peak_threshold or self.threshold * 3)
        self.sustained_threshold = int(sustained_threshold or int(self.threshold * 1.5))
        self.sustained_window_seconds = int(sustained_window_seconds)
        self.alert_cooldown_seconds = int(alert_cooldown_seconds)
        self.packet_history = defaultdict(deque)
        self.last_alert_at = {}

    def process_packet(self, packet):

        if not packet:
            return None

        source_ip = packet.get("source_ip")

        if not source_ip:
            return None

        timestamp = self._parse_timestamp(
            packet.get("timestamp")
        )

        history = self.packet_history[source_ip]

        history.append(timestamp)

        cutoff = timestamp - timedelta(seconds=self.sustained_window_seconds)
        while history and history[0] < cutoff:
            history.popleft()

        packet_count = sum(
            1 for item in history
            if item >= timestamp - timedelta(seconds=self.window_seconds)
        )
        sustained_count = len(history)
        sustained_rate = sustained_count / self.sustained_window_seconds

        if packet_count >= self.ddos_peak_threshold:
            classification = "DDOS"
            reason = "exceptional packet-rate peak"
        elif (
            sustained_count >= self.sustained_threshold * self.sustained_window_seconds
            and sustained_rate >= self.sustained_threshold
        ):
            classification = "DDOS"
            reason = "sustained elevated packet rate"
        elif packet_count >= self.threshold:
            classification = "ABNORMAL_TRAFFIC"
            reason = "short high-volume burst requires observation"
        else:
            return None

        key = (source_ip, classification)
        previous_alert = self.last_alert_at.get(key)
        if previous_alert and timestamp - previous_alert < timedelta(
            seconds=self.alert_cooldown_seconds
        ):
            return None

        self.last_alert_at[key] = timestamp
        is_ddos = classification == "DDOS"
        return {
            "type": classification,
            "classification": classification,
            "severity": "CRITICAL" if is_ddos else "HIGH",
            "source_ip": source_ip,
            "packets_per_second": packet_count,
            "peak_packets_per_second": packet_count,
            "sustained_packets_per_second": round(sustained_rate, 2),
            "threshold": self.threshold,
            "ddos_peak_threshold": self.ddos_peak_threshold,
            "sustained_threshold": self.sustained_threshold,
            "window_seconds": self.window_seconds,
            "sustained_window_seconds": self.sustained_window_seconds,
            "validation_reason": reason,
            "timestamp": timestamp.isoformat(),
            "message": (
                f"Validated traffic flood from {source_ip}: {packet_count} packets "
                f"within {self.window_seconds} second(s), sustained rate "
                f"{sustained_rate:.0f} packets/s"
                if is_ddos else
                f"High-volume traffic observed from {source_ip}: {packet_count} packets "
                f"within {self.window_seconds} second(s). Monitoring before DDoS escalation."
            ),
        }

    def reset_source(self, source_ip):

        self.packet_history.pop(
            source_ip,
            None
        )

        for key in list(self.last_alert_at):
            if key[0] == source_ip:
                self.last_alert_at.pop(key, None)

    def _parse_timestamp(self, timestamp):

        if not timestamp:
            return datetime.now()

        if isinstance(timestamp, datetime):
            return timestamp

        try:
            return datetime.fromisoformat(
                timestamp
            )

        except (ValueError, TypeError):

            return datetime.now()
