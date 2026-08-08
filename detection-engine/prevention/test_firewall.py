from firewall import WindowsFirewall


TEST_IP = "192.0.2.123"


def main():

    print("SentinelX Firewall Test")
    print("========================\n")

    print(f"Blocking test IP: {TEST_IP}")

    result = WindowsFirewall.block_ip(TEST_IP)

    print(result)

    if result.get("success"):

        print("\n Firewall rule created.")

        print("\nRemoving test rule...")

        result = WindowsFirewall.unblock_ip(
            TEST_IP
        )

        print(result)

        if result.get("success"):
            print("\n Test rule removed.")


if __name__ == "__main__":
    main()