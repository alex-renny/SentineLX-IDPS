import os
import sys
from datetime import datetime

# Make detection-engine available for imports
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from prevention.prevention_engine import PreventionEngine

class AlertManager:

    def __init__(
        self,
        prevention_engine=None
    ):

        self.prevention_engine = (
            prevention_engine
            or PreventionEngine(
                dry_run=True,
                default_block_seconds=300
            )
        )

        self.alert_history = []

    # ========================================================
    # PROCESS ALERT
    # ========================================================

    def process_alert(self, alert):

        if not alert:
            return None

        normalized = self._normalize_alert(
            alert
        )

        self.alert_history.append(
            normalized
        )

        # Keep memory bounded
        if len(self.alert_history) > 1000:

            self.alert_history = (
                self.alert_history[-1000:]
            )

        # ----------------------------------------------------
        # PREVENTION
        # ----------------------------------------------------

        prevention_result = (
            self.prevention_engine.process_alert(
                normalized
            )
        )

        normalized["prevention"] = (
            prevention_result
        )

        return normalized

    # ========================================================
    # NORMALIZE ALERT
    # ========================================================

    def _normalize_alert(self, alert):

        return {
            "id": self._generate_id(),

            "type": alert.get(
                "type",
                "UNKNOWN"
            ),

            "severity": alert.get(
                "severity",
                "MEDIUM"
            ),

            "source_ip": alert.get(
                "source_ip"
            ),

            "target": alert.get(
                "target"
            ),

            "service": alert.get(
                "service"
            ),

            "message": alert.get(
                "message",
                "Security event detected"
            ),

            "detected_at": alert.get(
                "timestamp",
                datetime.now().isoformat()
            )
        }

    # ========================================================
    # GENERATE EVENT ID
    # ========================================================

    def _generate_id(self):

        timestamp = (
            datetime.now()
            .strftime("%Y%m%d%H%M%S%f")
        )

        return f"SX-{timestamp}"

    # ========================================================
    # GET RECENT ALERTS
    # ========================================================

    def get_recent_alerts(
        self,
        limit=50
    ):

        return self.alert_history[-limit:]

    # ========================================================
    # GET BLOCKED IPS
    # ========================================================

    def get_blocked_ips(self):

        return (
            self.prevention_engine
            .blocked_ips
        )