import subprocess
import re


class WindowsFirewall:

    PREFIX = "SentinelX-IDPS"

    @staticmethod
    def _validate_ip(ip):
        """
        Only allow IPv4 addresses.
        Prevents shell-command injection.
        """
        pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

        if not re.match(pattern, ip):
            raise ValueError(f"Invalid IPv4 address: {ip}")

        parts = ip.split(".")

        if any(int(part) > 255 for part in parts):
            raise ValueError(f"Invalid IPv4 address: {ip}")

        return ip

    @classmethod
    def rule_name(cls, ip):
        ip = cls._validate_ip(ip)
        return f"{cls.PREFIX}-{ip}"

    @classmethod
    def block_ip(cls, ip):

        ip = cls._validate_ip(ip)
        rule_name = cls.rule_name(ip)

        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
            "enable=yes"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=False
        )

        if result.returncode != 0:

            return {
                "success": False,
                "action": "BLOCK_FAILED",
                "ip": ip,
                "error": result.stderr.strip()
            }

        return {
            "success": True,
            "action": "BLOCKED",
            "ip": ip,
            "rule": rule_name
        }

    @classmethod
    def unblock_ip(cls, ip):

        ip = cls._validate_ip(ip)
        rule_name = cls.rule_name(ip)

        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=False
        )

        if result.returncode != 0:

            return {
                "success": False,
                "action": "UNBLOCK_FAILED",
                "ip": ip,
                "error": result.stderr.strip()
            }

        return {
            "success": True,
            "action": "UNBLOCKED",
            "ip": ip,
            "rule": rule_name
        }