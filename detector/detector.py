import time
from collections import deque, defaultdict


class AnomalyDetector:
    """
    Uses two deque-based sliding windows (per-IP and global)
    to detect anomalous request rates.
    Window duration: 60 seconds.
    Eviction: remove entries older than window_seconds on every check.
    """

    def __init__(self, config, baseline):
        self.window_seconds = config.get("sliding_window_seconds", 60)
        self.zscore_threshold = config.get("zscore_threshold", 3.0)
        self.rate_multiplier = config.get("rate_multiplier_threshold", 5.0)
        self.error_surge_multiplier = config.get("error_surge_multiplier", 3.0)
        self.baseline = baseline

        # Global sliding window: deque of timestamps
        self.global_window = deque()

        # Per-IP sliding windows: {ip: deque of timestamps}
        self.ip_windows = defaultdict(deque)

        # Per-IP error windows: {ip: deque of timestamps}
        self.ip_error_windows = defaultdict(deque)

    def record(self, ip, is_error=False):
        """
        Record a request from an IP.
        Returns (ip_anomaly: bool, global_anomaly: bool, reason: str)
        """
        now = time.time()
        cutoff = now - self.window_seconds

        # Add to global window
        self.global_window.append(now)

        # Add to per-IP window
        self.ip_windows[ip].append(now)

        # Add to error window if error
        if is_error:
            self.ip_error_windows[ip].append(now)

        # Evict old entries from global window
        while self.global_window and self.global_window[0] < cutoff:
            self.global_window.popleft()

        # Evict old entries from IP window
        while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
            self.ip_windows[ip].popleft()

        # Evict old entries from error window
        while self.ip_error_windows[ip] and self.ip_error_windows[ip][0] < cutoff:
            self.ip_error_windows[ip].popleft()

        # Calculate rates (requests per second)
        global_rate = len(self.global_window) / self.window_seconds
        ip_rate = len(self.ip_windows[ip]) / self.window_seconds
        error_rate = len(self.ip_error_windows[ip]) / self.window_seconds

        # Check if IP has error surge — tighten thresholds
        zscore_threshold = self.zscore_threshold
        rate_multiplier = self.rate_multiplier
        if error_rate > self.baseline.error_baseline * self.error_surge_multiplier:
            zscore_threshold = max(1.5, zscore_threshold * 0.6)
            rate_multiplier = max(2.0, rate_multiplier * 0.6)

        # Check per-IP anomaly
        ip_zscore = self.baseline.get_zscore(ip_rate)
        ip_anomaly = False
        ip_reason = ""

        if ip_zscore > zscore_threshold:
            ip_anomaly = True
            ip_reason = (
                f"z-score={ip_zscore:.2f} > {zscore_threshold} "
                f"rate={ip_rate:.2f}/s"
            )
        elif ip_rate > self.baseline.effective_mean * rate_multiplier:
            ip_anomaly = True
            ip_reason = (
                f"rate={ip_rate:.2f}/s > "
                f"{rate_multiplier}x baseline "
                f"mean={self.baseline.effective_mean:.2f}"
            )

        # Check global anomaly
        global_zscore = self.baseline.get_zscore(global_rate)
        global_anomaly = False
        global_reason = ""

        if global_zscore > self.zscore_threshold:
            global_anomaly = True
            global_reason = (
                f"global z-score={global_zscore:.2f} "
                f"rate={global_rate:.2f}/s"
            )
        elif global_rate > self.baseline.effective_mean * self.rate_multiplier:
            global_anomaly = True
            global_reason = (
                f"global rate={global_rate:.2f}/s > "
                f"{self.rate_multiplier}x baseline"
            )

        return ip_anomaly, global_anomaly, ip_reason, global_reason

    def get_top_ips(self, n=10):
        """Return top N IPs by request count in current window."""
        return sorted(
            [(ip, len(w)) for ip, w in self.ip_windows.items()],
            key=lambda x: x[1],
            reverse=True
        )[:n]

    def get_global_rate(self):
        """Return current global requests per second."""
        return len(self.global_window) / self.window_seconds
