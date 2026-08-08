from datetime import datetime, timedelta
from .firewall import WindowsFirewall

class PreventionEngine:

    def __init__(
    self,
    dry_run=True,
    default_block_seconds=300
):

        self.dry_run = dry_run

        self.default_block_seconds = (
            default_block_seconds
        )

        self.trusted_ips = {
            "127.0.0.1",
            "::1"
        }

        self.blocked_ips = {}

    # ========================================================
    # TRUSTED IP
    # ========================================================

    def is_trusted(self, ip):

        return ip in self.trusted_ips

    def add_trusted_ip(self, ip):

        self.trusted_ips.add(ip)

    def remove_trusted_ip(self, ip):

        self.trusted_ips.discard(ip)

    # ========================================================
    # BLOCK DECISION
    # ========================================================

    def should_block(self, alert):

        if not alert:
            return False

        source_ip = alert.get("source_ip")

        if not source_ip:
            return False

        if self.is_trusted(source_ip):
            return False

        severity = (
            alert.get("severity", "")
            .upper()
        )

        return severity in {
            "HIGH",
            "CRITICAL"
        }

    # ========================================================
    # BLOCK IP
    # ========================================================

    def block_ip(
        self,
        ip,
        reason="Security alert",
        duration=None
    ):

        if self.is_trusted(ip):

            return {
                "success": False,
                "action": "SKIPPED",
                "reason": "Trusted IP",
                "ip": ip
            }

        if duration is None:

            duration = (
                self.default_block_seconds
            )

        expires_at = (
            datetime.now()
            + timedelta(seconds=duration)
        )

        self.blocked_ips[ip] = {
            "ip": ip,
            "reason": reason,
            "blocked_at":
                datetime.now().isoformat(),
            "expires_at":
                expires_at.isoformat()
        }

        # ----------------------------------------------------
        # DRY RUN
        # ----------------------------------------------------

        if self.dry_run:

            return {
                "success": True,
                "action": "DRY_RUN_BLOCK",
                "ip": ip,
                "reason": reason,
                "expires_at":
                    expires_at.isoformat()
            }

        # ----------------------------------------------------
        # REAL WINDOWS FIREWALL BLOCK
        # ----------------------------------------------------

        firewall_result = WindowsFirewall.block_ip(ip)

        return {
            **firewall_result,
            "reason": reason,
            "expires_at":
                expires_at.isoformat()
        }

    # ========================================================
    # UNBLOCK
    # ========================================================

    def unblock_ip(self, ip):

        if ip in self.blocked_ips:

            del self.blocked_ips[ip]

            return {
                "success": True,
                "action": "UNBLOCKED",
                "ip": ip
            }

        return {
            "success": False,
            "action": "NOT_FOUND",
            "ip": ip
        }

    # ========================================================
    # CLEAN EXPIRED BLOCKS
    # ========================================================

    def cleanup_expired(self):

        now = datetime.now()

        expired = []

        for ip, data in list(
            self.blocked_ips.items()
        ):

            expires_at = datetime.fromisoformat(
                data["expires_at"]
            )

            if now >= expires_at:

                expired.append(ip)

        for ip in expired:

            self.unblock_ip(ip)

        return expired

    # ========================================================
    # PROCESS ALERT
    # ========================================================

    def process_alert(self, alert):

        if not alert:

            return None

        if not self.should_block(alert):

            return {
                "action": "MONITOR",
                "ip":
                    alert.get("source_ip"),
                "reason":
                    "Alert does not meet blocking policy"
            }

        return self.block_ip(
            ip=alert.get("source_ip"),
            reason=alert.get(
                "message",
                alert.get("type", "Security alert")
            )
        )