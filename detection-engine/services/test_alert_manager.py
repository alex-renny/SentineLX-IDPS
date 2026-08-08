from services.alert_manager import AlertManager


def main():

    manager = AlertManager()

    alert = {
        "type": "PORT_SCAN",
        "severity": "HIGH",
        "source_ip": "192.168.1.100",
        "ports_detected": 30,
        "window_seconds": 10,
        "message": "Possible port scan detected"
    }

    print("\n🚨 Incoming security alert")
    print(alert)

    result = manager.process_alert(alert)

    print("\n🛡️ Alert Manager result")
    print(result)


if __name__ == "__main__":
    main()