"""Read normalized failed-authentication events written by the API/log shipper."""

import json
import os


SUPPORTED_SERVICES = {"SSH", "FTP", "HTTP", "RDP"}


class AuthEventReader:
    """Tail a JSONL file without reprocessing events already consumed."""

    def __init__(self, path=None):
        default_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "data",
            "auth-events.jsonl",
        )
        self.path = path or os.getenv("SENTINELX_AUTH_EVENT_FILE", default_path)
        self.position = 0

    def read_events(self):
        if not os.path.exists(self.path):
            return []

        if os.path.getsize(self.path) < self.position:
            self.position = 0

        events = []

        with open(self.path, "r", encoding="utf-8") as stream:
            stream.seek(self.position)

            for line in stream:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if self._is_supported_failure(event):
                    events.append(event)

            self.position = stream.tell()

        return events

    @staticmethod
    def _is_supported_failure(event):
        return (
            event.get("event_type") == "AUTH_FAILURE"
            and bool(event.get("source_ip"))
            and str(event.get("service", "")).upper() in SUPPORTED_SERVICES
        )
