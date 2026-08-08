import time
import json
from datetime import datetime

from network.monitor import capture_traffic


def run_worker():

    print(
        json.dumps({
            "type": "ENGINE_STATUS",
            "status": "STARTED",
            "timestamp": datetime.now().isoformat()
        }),
        flush=True
    )

    while True:

        try:

            packets, alerts = capture_traffic(
                duration=5
            )

            for alert in alerts:

                print(
                    json.dumps({
                        "type": "SECURITY_ALERT",
                        "alert": alert
                    }),
                    flush=True
                )

            print(
                json.dumps({
                    "type": "SCAN_COMPLETE",
                    "timestamp": datetime.now().isoformat(),
                    "packet_count": len(packets),
                    "alert_count": len(alerts)
                }),
                flush=True
            )

        except KeyboardInterrupt:

            print(
                json.dumps({
                    "type": "ENGINE_STATUS",
                    "status": "STOPPED",
                    "timestamp": datetime.now().isoformat()
                }),
                flush=True
            )

            break

        except Exception as error:

            print(
                json.dumps({
                    "type": "ENGINE_ERROR",
                    "error": str(error),
                    "timestamp": datetime.now().isoformat()
                }),
                flush=True
            )

            time.sleep(2)


if __name__ == "__main__":
    run_worker()