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

        # (source_ip, service) -> deque of failed attempts
        self.failed_attempts = defaultdict(deque)
        self.last_alert_at = {}

    def process_event(self, event):

        if not event:
            return None

        # We only process authentication failures.
        if event.get("event_type") != "AUTH_FAILURE":
            return None

        source_ip = event.get("source_ip")
        service = str(event.get("service", "unknown")).upper()

        if not source_ip:
            return None

        timestamp = self._parse_timestamp(
            event.get("timestamp")
        )

        key = (source_ip, service)
        attempts = self.failed_attempts[key]

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
        ):
            previous_alert = self.last_alert_at.get(key)

            # Allow a new alert after the current window, but do not emit one
            # for every failed login after the threshold is crossed.
            if previous_alert and timestamp - previous_alert < timedelta(
                seconds=self.window_seconds
            ):
                return None

            self.last_alert_at[key] = timestamp

            return {
                "type": "BRUTE_FORCE",
                "severity": (
                    "CRITICAL"
                    if attempt_count >= self.threshold * 2
                    else "HIGH"
                ),
                "source_ip": source_ip,
                "target": event.get(
                    "target",
                    "unknown"
                ),
                "service": service,
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

        for key in list(self.failed_attempts):
            if key[0] == source_ip:
                self.failed_attempts.pop(key, None)
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
