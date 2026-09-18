import os
import sys
from datetime import datetime


# ============================================================
# Make detection-engine available for imports
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ============================================================
# Prevention Engine
# ============================================================

from prevention.prevention_engine import PreventionEngine


# ============================================================
# Alert Manager
# ============================================================

class AlertManager:

    def __init__(self, prevention_engine=None):

        self.prevention_engine = (
            prevention_engine
            or PreventionEngine()
        )

        self.alert_history = []


    # ========================================================
    # PROCESS ALERT
    # ========================================================

    def process_alert(self, alert):

        if not alert:
            return None

        normalized = self._normalize_alert(alert)

        self.alert_history.append(normalized)

        # Keep memory bounded
        if len(self.alert_history) > 1000:
            self.alert_history = self.alert_history[-1000:]

        # ----------------------------------------------------
        # PREVENTION
        # ----------------------------------------------------

        prevention_result = None

        source_ip = normalized.get("source_ip")
        alert_type = normalized.get("type")

        if source_ip and self.prevention_engine.should_prevent(alert_type):

            prevention_result = (
                self.prevention_engine.block_ip(
                    source_ip,
                    reason=f"{alert_type} detected",
                    source="auto",
                )
            )

        normalized["prevention"] = prevention_result
        normalized["prevention_action"] = (
            prevention_result.get("action")
            if prevention_result
            else "NONE"
        )

        timeline = [
            {
                "status": "DETECTED",
                "at": normalized["detected_at"],
                "note": "Alert created by detection engine",
            }
        ]

        if (
            prevention_result
            and prevention_result.get("success")
            and prevention_result.get("action") == "BLOCKED"
        ):
            normalized["status"] = "BLOCKED"
            timeline.append({
                "status": "BLOCKED",
                "at": datetime.now().isoformat(),
                "note": (
                    f"Windows Firewall rule {prevention_result.get('rule')}"
                    if prevention_result.get("rule")
                    else "Automatic prevention"
                ),
            })
        else:
            normalized["status"] = "DETECTED"

        normalized["timeline"] = timeline

        return normalized


    # ========================================================
    # NORMALIZE ALERT
    # ========================================================

    def _normalize_alert(self, alert):

        return {
    "id": self._generate_id(),

    "status": "DETECTED",

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

    "destination_ip": alert.get(
        "destination_ip"
    ),

    "ports_detected": alert.get(
        "ports_detected",
        0
    ),

    "attempts": alert.get("attempts", 0),

    "packets_per_second": alert.get("packets_per_second", 0),

    "threshold": alert.get("threshold", 0),

    "window_seconds": alert.get(
        "window_seconds",
        0
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

        timestamp = datetime.now().strftime(
            "%Y%m%d%H%M%S%f"
        )

        return f"SX-{timestamp}"


    # ========================================================
    # GET RECENT ALERTS
    # ========================================================

    def get_recent_alerts(self, limit=50):

        return self.alert_history[-limit:]


    # ========================================================
    # GET BLOCKED IPS
    # ========================================================

    def get_blocked_ips(self):

        # PreventionEngine currently may not expose
        # blocked_ips, so safely return an empty list
        # if the attribute does not exist.

        return [
            item.get("ip", item) if isinstance(item, dict) else item
            for item in getattr(
                self.prevention_engine,
                "blocked_ips",
                []
            )
        ]


    # ========================================================
    # HANDLE ALERT
    # ========================================================

    def handle_alert(self, alert):

        if not alert:
            return None

        return self.process_alert(alert)
