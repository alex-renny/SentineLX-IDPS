import os

from firewall import WindowsFirewall


TEST_IP = "192.0.2.123"


def main():

    print("SentinelX Firewall Test")
    print("========================\n")

    print(f"Rule name: {WindowsFirewall.rule_name(TEST_IP)}")
    assert (
        WindowsFirewall.rule_name(TEST_IP)
        == "SentinelX-IDPS-BLOCK-192_0_2_123"
    )
    assert (
        WindowsFirewall.ip_from_rule_name(
            "SentinelX-IDPS-BLOCK-192_0_2_123"
        )
        == TEST_IP
    )

    live = os.getenv("SENTINELX_FIREWALL_LIVE", "false").lower() == "true"

    if not live:
        print(
            "Skipping live netsh changes. "
            "Set SENTINELX_FIREWALL_LIVE=true to create and delete a TEST-NET rule."
        )
        return

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
