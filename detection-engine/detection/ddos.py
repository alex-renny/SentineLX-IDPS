from collections import defaultdict, deque
from datetime import datetime, timedelta


class DDoSDetector:

    def __init__(
        self,
        threshold=1000,
        window_seconds=1
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds

        # source_ip -> packet timestamps
        self.packet_history = defaultdict(deque)

        # Prevent repeated alerts
        self.alerted_sources = set()

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

        cutoff = timestamp - timedelta(
            seconds=self.window_seconds
        )

        while history and history[0] < cutoff:
            history.popleft()

        packet_count = len(history)

        if (
            packet_count >= self.threshold
            and source_ip not in self.alerted_sources
        ):

            self.alerted_sources.add(source_ip)

            return {
                "type": "DDOS",
                "severity": "CRITICAL",
                "source_ip": source_ip,
                "packets_per_second": packet_count,
                "threshold": self.threshold,
                "window_seconds": self.window_seconds,
                "timestamp": timestamp.isoformat(),
                "message": (
                    f"Possible traffic flood detected "
                    f"from {source_ip}: "
                    f"{packet_count} packets within "
                    f"{self.window_seconds} second"
                )
            }

        return None

    def reset_source(self, source_ip):

        self.packet_history.pop(
            source_ip,
            None
        )

        self.alerted_sources.discard(
            source_ip
        )

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