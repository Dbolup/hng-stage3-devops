import time
import threading


class Unbanner:
    """
    Runs in background thread.
    Checks every 30 seconds if any ban has expired and releases it.
    Sends Slack notification on every unban.
    """

    def __init__(self, blocker, notifier, audit_logger):
        self.blocker = blocker
        self.notifier = notifier
        self.audit_logger = audit_logger
        self.running = True

    def start(self):
        """Start the unbanner in a background thread."""
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()
        print("[unbanner] Started background unban checker")

    def _run(self):
        while self.running:
            self._check_bans()
            time.sleep(30)

    def _check_bans(self):
        now = time.time()
        # Copy to avoid mutation during iteration
        bans = dict(self.blocker.get_active_bans())

        for ip, unban_time in bans.items():
            if unban_time == -1:
                continue  # Permanent ban — skip

            if now >= unban_time:
                self.blocker.unban(ip)
                ban_count = self.blocker.ban_counts[ip]

                self.notifier.send_unban_alert(ip, ban_count)
                self.audit_logger.log(
                    action="UNBAN",
                    ip=ip,
                    condition="ban_expired",
                    rate=0,
                    baseline=0,
                    duration="expired"
                )
