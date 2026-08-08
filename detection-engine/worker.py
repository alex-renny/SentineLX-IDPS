import json
import time
from datetime import datetime

from detection.port_scan import PortScanDetector
from detection.brute_force import BruteForceDetector
from detection.ddos import DDoSDetector

from network.monitor import capture_traffic
from services.alert_manager import AlertManager


# ============================================================
# DETECTORS
# ============================================================

port_scan_detector = PortScanDetector(
    threshold=30,
    window_seconds=10
)

brute_force_detector = BruteForceDetector(
    threshold=20,
    window_seconds=60
)

ddos_detector = DDoSDetector(
    threshold=1000,
    window_seconds=1
)

alert_manager = AlertManager()


# ============================================================
# ALERT MANAGER
# ============================================================

alert_manager = AlertManager()


# ============================================================
# ENGINE STATUS
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


def emit_status(status):

    emit({
        "type": "ENGINE_STATUS",
        "status": status,
        "timestamp": datetime.now().isoformat()
    })


# ============================================================
# PROCESS ALERTS
# ============================================================

def process_alerts(alerts):

    processed_alerts = []

    for alert in alerts:

        try:

            processed = alert_manager.process_alert(
                alert
            )

            if processed:

                processed_alerts.append(
                    processed
                )

        except Exception as error:

            emit({
                "type": "ENGINE_ERROR",
                "timestamp": datetime.now().isoformat(),
                "component": "alert_manager",
                "error": str(error)
            })

    return processed_alerts


# ============================================================
# NETWORK SCAN
# ============================================================

def run_network_detection():

    try:

        packets, network_alerts = capture_traffic(
            duration=5
        )

        # Send detected alerts through Alert Manager
        alerts = process_alerts(
            network_alerts
        )

        emit({
            "type": "SCAN_COMPLETE",
            "timestamp": datetime.now().isoformat(),
            "packet_count": len(packets),
            "alert_count": len(alerts),
            "alerts": alerts
        })

        return alerts

    except Exception as error:

        emit({
            "type": "ENGINE_ERROR",
            "timestamp": datetime.now().isoformat(),
            "component": "network",
            "error": str(error)
        })

        return []


# ============================================================
# TEST AUTHENTICATION EVENT
# ============================================================

def test_brute_force_detection():

    """
    Development-only authentication event test.

    Real Windows/application authentication events
    will be connected later.
    """

    source_ip = "192.168.1.100"

    for _ in range(20):

        event = {

            "event_type": "AUTH_FAILURE",

            "source_ip": source_ip,

            "target": "test-account",

            "service": "SSH",

            "timestamp":
                datetime.now().isoformat()
        }

        alert = brute_force_detector.process_event(
            event
        )

        if alert:

            processed = alert_manager.process_alert(
                alert
            )

            emit({
                "type": "SECURITY_ALERT",
                "timestamp":
                    datetime.now().isoformat(),
                "alert": processed
            })

            break


# ============================================================
# MAIN ENGINE
# ============================================================

def main():

    emit_status("STARTED")

    emit({
        "type": "ENGINE_INFO",
        "message":
            "SentinelX detection engine started",
        "timestamp":
            datetime.now().isoformat()
    })

    while True:

        run_network_detection()

        # Small delay prevents unnecessary CPU usage.
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
            "timestamp":
                datetime.now().isoformat(),
            "error": str(error)
        })