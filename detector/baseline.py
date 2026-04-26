import time
import math
from collections import deque, defaultdict


class BaselineTracker:
    """
    Tracks per-second request counts over a 30-minute rolling window.
    Recalculates mean and stddev every 60 seconds.
    Maintains per-hour slots and prefers current hour when enough data exists.
    """

    def __init__(self, config):
        self.window_minutes = config.get("baseline_window_minutes", 30)
        self.recalc_interval = config.get("baseline_recalc_interval", 60)
        self.floor_mean = config.get("baseline_floor_mean", 1.0)
        self.floor_stddev = config.get("baseline_floor_stddev", 0.5)

        # Rolling window: stores (timestamp, count) tuples
        self.window = deque()

        # Per-hour slots: {hour_int: [per_second_counts]}
        self.hourly_slots = defaultdict(list)

        # Current per-second accumulator
        self.current_second = int(time.time())
        self.current_count = 0

        # Computed baseline values
        self.effective_mean = self.floor_mean
        self.effective_stddev = self.floor_stddev
        self.error_baseline = 0.1

        # Recalculation tracking
        self.last_recalc = time.time()

    def record_request(self, is_error=False):
        """Call this for every incoming request."""
        now = int(time.time())

        if now != self.current_second:
            # Save completed second into rolling window
            self.window.append((self.current_second, self.current_count))

            # Save into hourly slot
            hour = int(time.strftime("%H", time.localtime(self.current_second)))
            self.hourly_slots[hour].append(self.current_count)

            # Evict entries older than window_minutes from deque
            cutoff = now - (self.window_minutes * 60)
            while self.window and self.window[0][0] < cutoff:
                self.window.popleft()

            self.current_second = now
            self.current_count = 0

        self.current_count += 1

        # Recalculate baseline every recalc_interval seconds
        if time.time() - self.last_recalc >= self.recalc_interval:
            self._recalculate()
            self.last_recalc = time.time()

    def _recalculate(self):
        """
        Compute mean and stddev from rolling window.
        Prefer current hour's data if it has >= 60 data points.
        """
        current_hour = int(time.strftime("%H"))
        hourly_data = self.hourly_slots.get(current_hour, [])

        if len(hourly_data) >= 60:
            # Enough current-hour data — use it
            data = hourly_data[-self.window_minutes * 60:]
        else:
            # Fall back to full rolling window
            data = [count for _, count in self.window]

        if len(data) < 2:
            return

        mean = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        stddev = math.sqrt(variance)

        # Apply floor values
        self.effective_mean = max(mean, self.floor_mean)
        self.effective_stddev = max(stddev, self.floor_stddev)

        print(
            f"[baseline] Recalculated — "
            f"mean={self.effective_mean:.2f} "
            f"stddev={self.effective_stddev:.2f} "
            f"samples={len(data)}"
        )

    def get_zscore(self, rate):
        """Calculate z-score for a given rate."""
        if self.effective_stddev == 0:
            return 0
        return (rate - self.effective_mean) / self.effective_stddev
