import ipaddress
import os
import subprocess
from datetime import datetime


class PreventionEngine:

    def __init__(self):
        self.mode = os.getenv(
            "SENTINELX_PREVENTION_MODE",
            "test"
        ).lower()

        self.rule_prefix = "SentinelX-IDPS-BLOCK"

        print(
        f"[PREVENTION] Prevention Engine initialized "
        f"(mode={self.mode})",
        flush=True
    )

    # ========================================================
    # IP VALIDATION
    # ========================================================

    def validate_ip(self, ip):

        try:
            address = ipaddress.ip_address(ip)

            if address.is_unspecified:
                return False

            if address.is_multicast:
                return False

            if address.is_loopback:
                return False

            return True

        except ValueError:
            return False

    # ========================================================
    # RULE NAME
    # ========================================================

    def rule_name(self, ip):

        safe_ip = ip.replace(":", "_").replace(".", "_")

        return f"{self.rule_prefix}-{safe_ip}"

    # ========================================================
    # BLOCK IP
    # ========================================================

    def block_ip(self, ip, reason="Security alert"):

        timestamp = datetime.now().isoformat()

        if not self.validate_ip(ip):

            return {
                "success": False,
                "action": "BLOCK",
                "ip": ip,
                "reason": "Invalid or protected IP",
                "timestamp": timestamp
            }

        rule = self.rule_name(ip)

        # ----------------------------------------------------
        # TEST MODE
        # ----------------------------------------------------

        if self.mode != "active":

            return {
                "success": True,
                "action": "BLOCK_SIMULATED",
                "ip": ip,
                "rule": rule,
                "reason": reason,
                "mode": self.mode,
                "timestamp": timestamp
            }

        # ----------------------------------------------------
        # ACTIVE WINDOWS FIREWALL BLOCK
        # ----------------------------------------------------

        command = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                f"New-NetFirewallRule "
                f"-DisplayName '{rule}' "
                f"-Direction Inbound "
                f"-Action Block "
                f"-RemoteAddress '{ip}' "
                f"-Profile Any "
                f"-Enabled True "
                f"-ErrorAction Stop"
            )
        ]

        try:

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=15
            )

            if result.returncode != 0:

                return {
                    "success": False,
                    "action": "BLOCK_FAILED",
                    "ip": ip,
                    "rule": rule,
                    "reason": reason,
                    "error": result.stderr.strip(),
                    "timestamp": timestamp
                }

            return {
                "success": True,
                "action": "BLOCKED",
                "ip": ip,
                "rule": rule,
                "reason": reason,
                "mode": self.mode,
                "timestamp": timestamp
            }

        except Exception as error:

            return {
                "success": False,
                "action": "BLOCK_FAILED",
                "ip": ip,
                "rule": rule,
                "reason": reason,
                "error": str(error),
                "timestamp": timestamp
            }

    # ========================================================
    # UNBLOCK IP
    # ========================================================

    def unblock_ip(self, ip):

        timestamp = datetime.now().isoformat()

        if not self.validate_ip(ip):

            return {
                "success": False,
                "action": "UNBLOCK",
                "ip": ip,
                "reason": "Invalid IP",
                "timestamp": timestamp
            }

        rule = self.rule_name(ip)

        # ----------------------------------------------------
        # TEST MODE
        # ----------------------------------------------------

        if self.mode != "active":

            return {
                "success": True,
                "action": "UNBLOCK_SIMULATED",
                "ip": ip,
                "rule": rule,
                "mode": self.mode,
                "timestamp": timestamp
            }

        # ----------------------------------------------------
        # REMOVE WINDOWS FIREWALL RULE
        # ----------------------------------------------------

        command = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                f"Remove-NetFirewallRule "
                f"-DisplayName '{rule}' "
                f"-ErrorAction SilentlyContinue"
            )
        ]

        try:

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=15
            )

            return {
                "success": result.returncode == 0,
                "action": "UNBLOCKED",
                "ip": ip,
                "rule": rule,
                "mode": self.mode,
                "timestamp": timestamp
            }

        except Exception as error:

            return {
                "success": False,
                "action": "UNBLOCK_FAILED",
                "ip": ip,
                "rule": rule,
                "error": str(error),
                "timestamp": timestamp
            }