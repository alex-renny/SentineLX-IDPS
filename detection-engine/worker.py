import time
import json
from datetime import datetime

from network.monitor import capture_traffic


def emit_event(event):
    print(
        json.dumps(event),
        flush=True
    )


def run_worker():

    emit_event({
        "type": "ENGINE_STATUS",
        "status": "STARTED",
        "timestamp": datetime.now().isoformat()
    })

    while True:

        try:

            packets, alerts = capture_traffic(
                duration=5
            )

            # Send every detected security event
            for alert in alerts:

                emit_event({
                    "type": "SECURITY_ALERT",
                    "alert": alert
                })

            # Send monitoring statistics
            emit_event({
                "type": "SCAN_COMPLETE",
                "timestamp": datetime.now().isoformat(),
                "packet_count": len(packets),
                "alert_count": len(alerts)
            })

        except KeyboardInterrupt:

            emit_event({
                "type": "ENGINE_STATUS",
                "status": "STOPPED",
                "timestamp": datetime.now().isoformat()
            })

            break

        except Exception as error:

            emit_event({
                "type": "ENGINE_ERROR",
                "error": str(error),
                "timestamp": datetime.now().isoformat()
            })

            time.sleep(2)


if __name__ == "__main__":
    run_worker()