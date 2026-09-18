import ipaddress
import os
import socket
import sys
from datetime import datetime

from prevention.firewall import WindowsFirewall


class PreventionEngine:

    PREVENTABLE_TYPES = {
        "PORT_SCAN",
        "BRUTE_FORCE",
        "DDOS",
    }

    def __init__(self):
        self.mode = os.getenv(
            "SENTINELX_PREVENTION_MODE",
            "test"
        ).lower()

        if self.mode not in {"test", "active"}:
            self.mode = "test"

        self.auto_block = os.getenv(
            "SENTINELX_PREVENTION_AUTO_BLOCK",
            "false"
        ).lower() == "true"
        # Active mode alone is not enough: Windows Firewall changes require a
        # second, deliberate opt-in. This keeps copied .env files safe.
        self.firewall_enforcement = os.getenv(
            "SENTINELX_FIREWALL_ENFORCEMENT",
            "disabled"
        ).lower() == "enabled"

        self.rule_prefix = WindowsFirewall.PREFIX
        self.blocked_ips = []
        self.allowlist = self._load_allowlist()

        print(
            f"[PREVENTION] Prevention Engine initialized "
            f"(mode={self.mode}, enforcement={self.firewall_enforcement}, "
            f"auto_block={self.auto_block})",
            file=sys.stderr,
            flush=True
        )

    def _load_allowlist(self):
        raw = os.getenv("SENTINELX_PREVENTION_ALLOWLIST", "")
        values = {item.strip() for item in raw.split(",") if item.strip()}
        values.update(self._local_ips())
        return values

    def _local_ips(self):
        local = {"127.0.0.1", "0.0.0.0"}

        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                local.add(info[4][0])
        except OSError:
            pass

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                local.add(sock.getsockname()[0])
        except OSError:
            pass

        return local

    def normalize_ip(self, ip):
        try:
            address = ipaddress.ip_address(str(ip).strip())
        except (ValueError, TypeError):
            return None

        if address.version != 4:
            return None

        if address.is_unspecified:
            return None

        if address.is_multicast:
            return None

        if address.is_loopback:
            return None

        if address.is_link_local:
            return None

        normalized = str(address)
        if normalized in self.allowlist:
            return None

        return normalized

    def validate_ip(self, ip):
        return self.normalize_ip(ip) is not None

    def rule_name(self, ip):
        return WindowsFirewall.rule_name(ip)

    def should_prevent(self, alert_type):
        return alert_type in self.PREVENTABLE_TYPES

    def _remember_block(self, ip, rule, action):
        self.blocked_ips = [
            item for item in self.blocked_ips if item.get("ip") != ip
        ]
        self.blocked_ips.append({
            "ip": ip,
            "rule": rule,
            "action": action,
            "timestamp": datetime.now().isoformat(),
        })

    def _forget_block(self, ip):
        self.blocked_ips = [
            item for item in self.blocked_ips if item.get("ip") != ip
        ]

    def list_rules(self):
        timestamp = datetime.now().isoformat()

        try:
            result = WindowsFirewall.list_rules()
        except Exception as error:
            return {
                "success": False,
                "action": "LIST_FAILED",
                "rules": [],
                "mode": self.mode,
                "error": str(error),
                "timestamp": timestamp,
            }

        return {
            **result,
            "mode": self.mode,
            "firewall_enforcement": "enabled" if self.firewall_enforcement else "disabled",
            "auto_block": self.auto_block,
            "timestamp": timestamp,
        }

    def block_ip(self, ip, reason="Security alert", source="manual"):
        timestamp = datetime.now().isoformat()
        origin = "auto" if source == "auto" else "manual"

        normalized_ip = self.normalize_ip(ip)
        if not normalized_ip:
            return {
                "success": False,
                "action": "BLOCK_REJECTED",
                "ip": ip,
                "reason": "Invalid, local, or protected IP",
                "mode": self.mode,
                "source": origin,
                "timestamp": timestamp,
            }

        ip = normalized_ip
        rule = self.rule_name(ip)

        if self.mode != "active" or not self.firewall_enforcement:
            result = {
                "success": True,
                "action": "BLOCK_SIMULATED",
                "ip": ip,
                "rule": rule,
                "reason": reason,
                "mode": self.mode,
                "enforcement": "disabled",
                "source": origin,
                "timestamp": timestamp,
            }
            self._remember_block(ip, rule, result["action"])
            return result

        if origin == "auto" and not self.auto_block:
            return {
                "success": True,
                "action": "BLOCK_PENDING",
                "ip": ip,
                "rule": rule,
                "reason": reason,
                "mode": self.mode,
                "source": origin,
                "message": (
                    "Detection validated this IP. Confirm Block IP in the "
                    "dashboard to create a Windows Firewall rule."
                ),
                "timestamp": timestamp,
            }

        try:
            firewall_result = WindowsFirewall.block_ip(ip)
        except Exception as error:
            return {
                "success": False,
                "action": "BLOCK_FAILED",
                "ip": ip,
                "rule": rule,
                "reason": reason,
                "mode": self.mode,
                "source": origin,
                "error": str(error),
                "timestamp": timestamp,
            }

        result = {
            **firewall_result,
            "reason": reason,
            "mode": self.mode,
            "source": origin,
            "timestamp": timestamp,
            "rule": firewall_result.get("rule", rule),
        }

        if result.get("success"):
            self._remember_block(ip, result["rule"], result["action"])

        return result

    def unblock_ip(self, ip):
        timestamp = datetime.now().isoformat()

        normalized_ip = self.normalize_ip(ip)
        if not normalized_ip:
            return {
                "success": False,
                "action": "UNBLOCK_REJECTED",
                "ip": ip,
                "reason": "Invalid IP",
                "mode": self.mode,
                "timestamp": timestamp,
            }

        ip = normalized_ip
        rule = self.rule_name(ip)

        if self.mode != "active" or not self.firewall_enforcement:
            self._forget_block(ip)
            return {
                "success": True,
                "action": "UNBLOCK_SIMULATED",
                "ip": ip,
                "rule": rule,
                "mode": self.mode,
                "enforcement": "disabled",
                "timestamp": timestamp,
            }

        try:
            firewall_result = WindowsFirewall.unblock_ip(ip)
        except Exception as error:
            return {
                "success": False,
                "action": "UNBLOCK_FAILED",
                "ip": ip,
                "rule": rule,
                "mode": self.mode,
                "error": str(error),
                "timestamp": timestamp,
            }

        result = {
            **firewall_result,
            "mode": self.mode,
            "timestamp": timestamp,
            "rule": firewall_result.get("rule", rule),
        }

        if result.get("success"):
            self._forget_block(ip)

        return result
