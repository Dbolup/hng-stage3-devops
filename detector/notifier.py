import requests
import json
import time
import os


class Notifier:
    """Sends Slack webhook alerts for ban, unban, and global anomaly events."""

    def __init__(self, config):
        self.webhook_url = os.environ.get(
            "SLACK_WEBHOOK_URL",
            config.get("slack_webhook_url", "")
        )

    def _send(self, message):
        if not self.webhook_url:
            print(f"[notifier] No webhook URL — would have sent: {message}")
            return
        try:
            requests.post(
                self.webhook_url,
                data=json.dumps({"text": message}),
                headers={"Content-Type": "application/json"},
                timeout=5
            )
        except Exception as e:
            print(f"[notifier] Slack error: {e}")

    def send_ban_alert(self, ip, condition, rate, baseline, duration):
        duration_str = "permanent" if duration == -1 else f"{duration} min"
        msg = (
            f":rotating_light: *IP BANNED*\n"
            f"IP: `{ip}`\n"
            f"Condition: {condition}\n"
            f"Rate: {rate:.2f} req/s\n"
            f"Baseline mean: {baseline:.2f} req/s\n"
            f"Ban duration: {duration_str}\n"
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self._send(msg)

    def send_unban_alert(self, ip, ban_count):
        msg = (
            f":white_check_mark: *IP UNBANNED*\n"
            f"IP: `{ip}`\n"
            f"Total bans: {ban_count}\n"
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self._send(msg)

    def send_global_alert(self, condition, rate, baseline):
        msg = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f"Condition: {condition}\n"
            f"Global rate: {rate:.2f} req/s\n"
            f"Baseline mean: {baseline:.2f} req/s\n"
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self._send(msg)
