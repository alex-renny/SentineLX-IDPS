from collections import defaultdict, deque
from datetime import datetime, timedelta


class BruteForceDetector:

    def __init__(
        self,
        threshold=20,
        window_seconds=60
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds

        # source_ip -> deque of failed attempts
        self.failed_attempts = defaultdict(deque)

        # Prevent repeated alerts
        self.alerted_sources = set()

    def process_event(self, event):

        if not event:
            return None

        # We only process authentication failures.
        if event.get("event_type") != "AUTH_FAILURE":
            return None

        source_ip = event.get("source_ip")

        if not source_ip:
            return None

        timestamp = self._parse_timestamp(
            event.get("timestamp")
        )

        attempts = self.failed_attempts[source_ip]

        attempts.append(timestamp)

        # Remove events outside the detection window
        cutoff = timestamp - timedelta(
            seconds=self.window_seconds
        )

        while attempts and attempts[0] < cutoff:
            attempts.popleft()

        attempt_count = len(attempts)

        if (
            attempt_count >= self.threshold
            and source_ip not in self.alerted_sources
        ):

            self.alerted_sources.add(source_ip)

            return {
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "source_ip": source_ip,
                "target": event.get(
                    "target",
                    "unknown"
                ),
                "service": event.get(
                    "service",
                    "unknown"
                ),
                "attempts": attempt_count,
                "window_seconds": self.window_seconds,
                "timestamp": timestamp.isoformat(),
                "message": (
                    f"Possible brute-force activity "
                    f"detected from {source_ip}: "
                    f"{attempt_count} failed authentication "
                    f"attempts within "
                    f"{self.window_seconds} seconds"
                )
            }

        return None

    def reset_source(self, source_ip):

        self.failed_attempts.pop(
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