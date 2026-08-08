from datetime import datetime

from brute_force import BruteForceDetector


def main():

    detector = BruteForceDetector(
        threshold=5,
        window_seconds=60
    )

    source_ip = "192.168.1.100"

    print("Testing brute-force detector...\n")

    for attempt in range(1, 7):

        event = {
            "event_type": "AUTH_FAILURE",
            "source_ip": source_ip,
            "target": "test-account",
            "service": "SSH",
            "timestamp": datetime.now().isoformat()
        }

        alert = detector.process_event(event)

        print(
            f"Attempt {attempt}:",
            "ALERT" if alert else "normal"
        )

        if alert:
            print("\n🚨 BRUTE FORCE DETECTED")
            print(alert)


if __name__ == "__main__":
    main()