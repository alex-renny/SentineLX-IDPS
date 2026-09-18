import os
import re
import subprocess


class WindowsFirewall:
    """
    Creates and removes SentinelX Windows Firewall rules.

    Rule example:
        SentinelX-IDPS-BLOCK-192_168_1_100
    """

    PREFIX = "SentinelX-IDPS-BLOCK"
    CREATE_NO_WINDOW = 0x08000000

    @staticmethod
    def _validate_ip(ip):
        """
        Only allow IPv4 addresses.
        Prevents shell-command injection.
        """
        if not isinstance(ip, str):
            raise ValueError("Invalid IPv4 address")

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
        safe_ip = ip.replace(".", "_")
        return f"{cls.PREFIX}-{safe_ip}"

    @classmethod
    def _run(cls, command):
        flags = cls.CREATE_NO_WINDOW if os.name == "nt" else 0

        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=False,
            timeout=20,
            creationflags=flags,
        )

    @classmethod
    def rule_exists(cls, ip):
        ip = cls._validate_ip(ip)
        rule_name = cls.rule_name(ip)

        result = cls._run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "show",
                "rule",
                f"name={rule_name}",
            ]
        )

        if result.returncode != 0:
            return False

        output = f"{result.stdout} {result.stderr}".lower()
        return "no rules match" not in output and rule_name.lower() in output

    @classmethod
    def block_ip(cls, ip):
        ip = cls._validate_ip(ip)
        rule_name = cls.rule_name(ip)

        if cls.rule_exists(ip):
            return {
                "success": True,
                "action": "BLOCKED",
                "ip": ip,
                "rule": rule_name,
                "already_present": True,
            }

        result = cls._run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
                "profile=any",
            ]
        )

        if result.returncode != 0:
            error = (result.stderr or result.stdout or "").strip()
            return {
                "success": False,
                "action": "BLOCK_FAILED",
                "ip": ip,
                "rule": rule_name,
                "error": error or "Windows Firewall rejected the block rule",
            }

        return {
            "success": True,
            "action": "BLOCKED",
            "ip": ip,
            "rule": rule_name,
            "already_present": False,
        }

    @classmethod
    def ip_from_rule_name(cls, rule_name):
        if not isinstance(rule_name, str):
            return None

        prefix = f"{cls.PREFIX}-"
        if not rule_name.startswith(prefix):
            return None

        candidate = rule_name[len(prefix):].replace("_", ".")
        try:
            return cls._validate_ip(candidate)
        except ValueError:
            return None

    @classmethod
    def list_rules(cls):
        result = cls._run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "show",
                "rule",
                "name=all",
            ]
        )

        if result.returncode != 0:
            error = (result.stderr or result.stdout or "").strip()
            return {
                "success": False,
                "action": "LIST_FAILED",
                "rules": [],
                "error": error or "Unable to query Windows Firewall rules",
            }

        rules = []
        current = {}

        for line in (result.stdout or "").splitlines():
            stripped = line.strip()
            lower = stripped.lower()

            if lower.startswith("rule name:"):
                if current.get("name", "").startswith(cls.PREFIX):
                    rules.append(current)

                current = {
                    "name": stripped.split(":", 1)[1].strip(),
                }
                continue

            if not current:
                continue

            if lower.startswith("remoteip:"):
                current["remote_ip"] = stripped.split(":", 1)[1].strip()
            elif lower.startswith("enabled:"):
                current["enabled"] = stripped.split(":", 1)[1].strip()
            elif lower.startswith("direction:"):
                current["direction"] = stripped.split(":", 1)[1].strip()

        if current.get("name", "").startswith(cls.PREFIX):
            rules.append(current)

        for rule in rules:
            if not rule.get("remote_ip"):
                inferred = cls.ip_from_rule_name(rule.get("name", ""))
                if inferred:
                    rule["remote_ip"] = inferred

        return {
            "success": True,
            "action": "LIST",
            "rules": rules,
        }

    @classmethod
    def unblock_ip(cls, ip):
        ip = cls._validate_ip(ip)
        rule_name = cls.rule_name(ip)

        if not cls.rule_exists(ip):
            return {
                "success": True,
                "action": "UNBLOCKED",
                "ip": ip,
                "rule": rule_name,
                "already_absent": True,
            }

        result = cls._run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"name={rule_name}",
            ]
        )

        if result.returncode != 0:
            error = (result.stderr or result.stdout or "").strip()
            return {
                "success": False,
                "action": "UNBLOCK_FAILED",
                "ip": ip,
                "rule": rule_name,
                "error": error or "Windows Firewall could not delete the rule",
            }

        return {
            "success": True,
            "action": "UNBLOCKED",
            "ip": ip,
            "rule": rule_name,
            "already_absent": False,
        }
