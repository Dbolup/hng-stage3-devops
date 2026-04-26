import subprocess
import time
from collections import defaultdict


class Blocker:
    """
    Manages iptables DROP rules for banned IPs.
    Tracks ban counts per IP to apply backoff schedule.
    """

    def __init__(self, config):
        # Ban schedule in minutes (-1 = permanent)
        raw_schedule = config.get("ban_schedule", [10, 30, 120, "permanent"])
        self.ban_schedule = []
        for entry in raw_schedule:
            if entry == "permanent":
                self.ban_schedule.append(-1)
            else:
                self.ban_schedule.append(int(entry))

        # {ip: ban_count} — how many times this IP has been banned
        self.ban_counts = defaultdict(int)

        # {ip: unban_timestamp} — when to unban (-1 = never)
        self.active_bans = {}

    def ban(self, ip):
        """Add iptables DROP rule for IP. Returns ban duration in minutes."""
        if ip in self.active_bans:
            return None  # Already banned

        count = self.ban_counts[ip]
        index = min(count, len(self.ban_schedule) - 1)
        duration = self.ban_schedule[index]

        # Add iptables rule
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
        except subprocess.CalledProcessError as e:
            print(f"[blocker] iptables error for {ip}: {e}")
            return None

        # Record ban
        self.ban_counts[ip] += 1
        if duration == -1:
            self.active_bans[ip] = -1  # Permanent
        else:
            self.active_bans[ip] = time.time() + (duration * 60)

        duration_str = "permanent" if duration == -1 else f"{duration} min"
        print(f"[blocker] Banned {ip} for {duration_str}")
        return duration

    def unban(self, ip):
        """Remove iptables DROP rule for IP."""
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
        except subprocess.CalledProcessError as e:
            print(f"[blocker] Error unbanning {ip}: {e}")

        self.active_bans.pop(ip, None)
        print(f"[blocker] Unbanned {ip}")

    def get_active_bans(self):
        """Return dict of currently active bans."""
        return dict(self.active_bans)

    def is_banned(self, ip):
        return ip in self.active_bans
