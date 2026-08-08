import json
import sys
import time
from datetime import datetime

from network.monitor import capture_traffic
from services.alert_manager import AlertManager


# ============================================================
# ALERT MANAGER
# ============================================================

alert_manager = AlertManager()


# ============================================================
# JSON OUTPUT
# ============================================================

def emit(data):
    """
    IMPORTANT:
    stdout must contain JSON only.
    """

    print(
        json.dumps(data),
        flush=True
    )


# ============================================================
# ENGINE STATUS
# ============================================================

def emit_status(status):

    emit({
        "type": "ENGINE_STATUS",
        "status": status,
        "timestamp": datetime.now().isoformat()
    })


# ============================================================
# NETWORK DETECTION
# ============================================================

def run_network_detection():

    try:

        packets, detected_alerts = capture_traffic(
            duration=5
        )

        processed_alerts = []

        # Process every detected security alert
        for alert in detected_alerts:

            processed = alert_manager.process_alert(
                alert
            )

            if processed:

                processed_alerts.append(
                    processed
                )

                # Send individual live security event
                emit({
                    "type": "SECURITY_ALERT",
                    "timestamp": datetime.now().isoformat(),
                    "alert": processed
                })

        # Send scan summary
        emit({
            "type": "SCAN_COMPLETE",
            "timestamp": datetime.now().isoformat(),
            "packet_count": len(packets),
            "alert_count": len(processed_alerts),
            "alerts": processed_alerts
        })

        return processed_alerts

    except Exception as error:

        emit({
            "type": "ENGINE_ERROR",
            "timestamp": datetime.now().isoformat(),
            "component": "network",
            "error": str(error)
        })

        return []


# ============================================================
# MAIN ENGINE
# ============================================================

def main():

    emit_status("STARTED")

    emit({
        "type": "ENGINE_INFO",
        "message": "SentinelX detection engine started",
        "timestamp": datetime.now().isoformat()
    })

    while True:

        run_network_detection()

        # Prevent unnecessary CPU usage
        time.sleep(1)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        emit_status("STOPPED")

    except Exception as error:

        emit({
            "type": "ENGINE_ERROR",
            "timestamp": datetime.now().isoformat(),
            "error": str(error)
        })