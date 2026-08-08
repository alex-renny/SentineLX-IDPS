from prevention_engine import PreventionEngine


def main():

    engine = PreventionEngine(
        dry_run=True,
        default_block_seconds=300
    )

    alert = {
        "type": "PORT_SCAN",
        "severity": "HIGH",
        "source_ip": "192.168.1.100",
        "message":
            "Possible port scanning detected"
    }

    print("Testing prevention engine...\n")

    result = engine.process_alert(alert)

    print(result)

    print("\nBlocked IPs:")
    print(engine.blocked_ips)


if __name__ == "__main__":
    main()