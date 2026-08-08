from datetime import datetime

from ddos import DDoSDetector


def main():

    detector = DDoSDetector(
        threshold=10,
        window_seconds=1
    )

    source_ip = "192.168.1.100"

    print("Testing DDoS detector...\n")

    alert = None

    for packet_number in range(1, 13):

        packet = {
            "source_ip": source_ip,
            "destination_ip": "192.168.1.10",
            "protocol": "TCP",
            "source_port": 4444,
            "destination_port": 443,
            "packet_size": 1400,
            "timestamp": datetime.now().isoformat()
        }

        alert = detector.process_packet(packet)

        print(
            f"Packet {packet_number}:",
            "ALERT" if alert else "normal"
        )

        if alert:

            print("\n🚨 DDOS DETECTED")
            print(alert)

            break


if __name__ == "__main__":
    main()