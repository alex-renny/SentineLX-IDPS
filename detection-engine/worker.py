import json
import os
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
# TEST MODE
# ============================================================

TEST_ALERT = os.getenv(
    "SENTINELX_TEST_ALERT",
    "false"
).lower() == "true"


test_alert_sent = False


# ============================================================
# JSON OUTPUT
# ============================================================

def emit(data):
    """
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
# CONTROLLED TEST ALERT
# ============================================================

def generate_test_alert():

    alert = {
        "type": "PORT_SCAN",
        "severity": "HIGH",
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.10",
        "ports_detected": 30,
        "window_seconds": 10,
        "timestamp": datetime.now().isoformat(),
        "message": (
            "TEST: Possible port scanning detected from "
            "192.168.1.100: 30 unique ports within 10 seconds"
        )
    }

    processed = alert_manager.process_alert(alert)

    if not processed:
        return

    emit({
        "type": "SECURITY_ALERT",
        "timestamp": datetime.now().isoformat(),
        "alert": processed
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

        for alert in detected_alerts:

            processed = alert_manager.process_alert(
                alert
            )

            if processed:

                processed_alerts.append(
                    processed
                )

                emit({
                    "type": "SECURITY_ALERT",
                    "timestamp": datetime.now().isoformat(),
                    "alert": processed
                })

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

    global test_alert_sent

    emit_status("STARTED")

    emit({
        "type": "ENGINE_INFO",
        "message": "SentinelX detection engine started",
        "timestamp": datetime.now().isoformat()
    })

    while True:

        # ----------------------------------------------------
        # SAFE INTEGRATION TEST
        # ----------------------------------------------------

        if TEST_ALERT and not test_alert_sent:

            generate_test_alert()

            test_alert_sent = True

        # ----------------------------------------------------
        # REAL NETWORK DETECTION
        # ----------------------------------------------------

        run_network_detection()

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