from alert_manager import AlertManager


def main():

    manager = AlertManager()

    alerts = [

        {
            "type": "PORT_SCAN",
            "severity": "HIGH",
            "source_ip": "192.0.2.100",
            "message":
                "Possible port scanning detected"
        },

        {
            "type": "BRUTE_FORCE",
            "severity": "HIGH",
            "source_ip": "192.0.2.101",
            "target": "admin",
            "service": "SSH",
            "message":
                "Repeated authentication failures"
        },

        {
            "type": "DDOS",
            "severity": "CRITICAL",
            "source_ip": "192.0.2.102",
            "message":
                "Possible traffic flood detected"
        }
    ]

    print(
        "\n=== SentinelX Alert Manager Test ===\n"
    )

    for alert in alerts:

        result = manager.process_alert(
            alert
        )

        print(result)
        print()

    print(
        "=== Recent Alerts ==="
    )

    for alert in manager.get_recent_alerts():

        print(
            alert["id"],
            "|",
            alert["type"],
            "|",
            alert["severity"],
            "|",
            alert["source_ip"]
        )

    print(
        "\n=== Blocked IPs ==="
    )

    print(
        manager.get_blocked_ips()
    )


if __name__ == "__main__":

    main()