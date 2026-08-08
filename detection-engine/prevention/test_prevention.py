from prevention.prevention_engine import PreventionEngine


def main():

    engine = PreventionEngine()

    test_ip = "192.168.1.100"

    print("\n================================")
    print(" SentinelX Prevention Test")
    print("================================")

    print("\nTesting BLOCK...")

    result = engine.block_ip(
        test_ip,
        reason="Test port scan detection"
    )

    print(result)

    print("\nTesting UNBLOCK...")

    result = engine.unblock_ip(test_ip)

    print(result)


if __name__ == "__main__":
    main()