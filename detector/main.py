import json
import time
import os
import yaml
import threading

from monitor import tail_log
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
import dashboard


# ─── Audit Logger ───────────────────────────────────────────
class AuditLogger:
    def __init__(self, log_path):
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self.log_path = log_path

    def log(self, action, ip, condition, rate, baseline, duration):
        entry = (
            f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
            f"ACTION={action} "
            f"ip={ip} | "
            f"condition={condition} | "
            f"rate={rate:.2f} | "
            f"baseline={baseline:.2f} | "
            f"duration={duration}"
        )
        print(f"[audit] {entry}")
        with open(self.log_path, "a") as f:
            f.write(entry + "\n")


# ─── Load Config ────────────────────────────────────────────
def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(config_path) as f:
        return yaml.safe_load(f)


# ─── Parse Log Line ─────────────────────────────────────────
def parse_line(line):
    try:
        data = json.loads(line)
        return {
            "ip": data.get("source_ip", ""),
            "status": int(data.get("status", 200)),
            "path": data.get("path", ""),
            "method": data.get("method", ""),
            "timestamp": data.get("timestamp", ""),
        }
    except Exception:
        return None


# ─── Main Loop ──────────────────────────────────────────────
def main():
    config = load_config()
    print("[main] Config loaded")

    audit = AuditLogger(config.get("audit_log", "/var/log/detector/audit.log"))
    baseline = BaselineTracker(config)
    detector = AnomalyDetector(config, baseline)
    blocker = Blocker(config)
    notifier = Notifier(config)
    unbanner = Unbanner(blocker, notifier, audit)

    # Start background services
    unbanner.start()
    dashboard.start(port=config.get("dashboard_port", 8080))

    # Track recently alerted IPs to avoid spam (10s cooldown)
    last_alerted = {}
    ALERT_COOLDOWN = 10

    print("[main] Starting log monitoring...")

    for line in tail_log(config["log_file"]):
        parsed = parse_line(line)
        if not parsed or not parsed["ip"]:
            continue

        ip = parsed["ip"]
        is_error = parsed["status"] >= 400

        # Record in baseline and detector
        baseline.record_request(is_error=is_error)
        ip_anomaly, global_anomaly, ip_reason, global_reason = detector.record(
            ip, is_error=is_error
        )

        now = time.time()

        # Handle per-IP anomaly
        if ip_anomaly and not blocker.is_banned(ip):
            last_alert = last_alerted.get(ip, 0)
            if now - last_alert > ALERT_COOLDOWN:
                last_alerted[ip] = now
                duration = blocker.ban(ip)
                if duration is not None:
                    rate = detector.get_global_rate()
                    notifier.send_ban_alert(
                        ip=ip,
                        condition=ip_reason,
                        rate=rate,
                        baseline=baseline.effective_mean,
                        duration=duration
                    )
                    audit.log(
                        action="BAN",
                        ip=ip,
                        condition=ip_reason,
                        rate=rate,
                        baseline=baseline.effective_mean,
                        duration=duration
                    )

        # Handle global anomaly (Slack alert only — no ban)
        if global_anomaly:
            last_alert = last_alerted.get("__global__", 0)
            if now - last_alert > ALERT_COOLDOWN:
                last_alerted["__global__"] = now
                notifier.send_global_alert(
                    condition=global_reason,
                    rate=detector.get_global_rate(),
                    baseline=baseline.effective_mean
                )
                audit.log(
                    action="GLOBAL_ALERT",
                    ip="N/A",
                    condition=global_reason,
                    rate=detector.get_global_rate(),
                    baseline=baseline.effective_mean,
                    duration="N/A"
                )

        # Update dashboard state
        dashboard.update_state({
            "banned_ips": blocker.get_active_bans(),
            "global_rate": detector.get_global_rate(),
            "top_ips": detector.get_top_ips(10),
            "effective_mean": baseline.effective_mean,
            "effective_stddev": baseline.effective_stddev,
        })


if __name__ == "__main__":
    main()
