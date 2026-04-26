import time
import threading
import psutil
from flask import Flask, render_template_string

app = Flask(__name__)

# Shared state — updated by main loop
state = {
    "banned_ips": {},
    "global_rate": 0.0,
    "top_ips": [],
    "effective_mean": 0.0,
    "effective_stddev": 0.0,
    "uptime_start": time.time(),
    "cpu_percent": 0.0,
    "memory_percent": 0.0,
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <title>HNG Anomaly Detector</title>
  <meta http-equiv="refresh" content="3">
  <style>
    body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
    h1 { color: #58a6ff; }
    h2 { color: #f0883e; border-bottom: 1px solid #30363d; padding-bottom: 5px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
    th { background: #161b22; color: #58a6ff; padding: 8px; text-align: left; }
    td { padding: 8px; border-bottom: 1px solid #21262d; }
    .metric { display: inline-block; background: #161b22; padding: 15px 25px;
              margin: 10px; border-radius: 8px; text-align: center; }
    .metric .value { font-size: 2em; color: #58a6ff; }
    .metric .label { color: #8b949e; font-size: 0.8em; }
    .banned { color: #f85149; }
    .safe { color: #3fb950; }
  </style>
</head>
<body>
  <h1>🛡️ HNG Anomaly Detection Dashboard</h1>

  <div>
    <div class="metric">
      <div class="value">{{ "%.2f"|format(state.global_rate) }}</div>
      <div class="label">Global req/s</div>
    </div>
    <div class="metric">
      <div class="value">{{ "%.2f"|format(state.effective_mean) }}</div>
      <div class="label">Baseline Mean</div>
    </div>
    <div class="metric">
      <div class="value">{{ "%.2f"|format(state.effective_stddev) }}</div>
      <div class="label">Baseline StdDev</div>
    </div>
    <div class="metric">
      <div class="value">{{ state.banned_ips|length }}</div>
      <div class="label">Banned IPs</div>
    </div>
    <div class="metric">
      <div class="value">{{ "%.1f"|format(state.cpu_percent) }}%</div>
      <div class="label">CPU Usage</div>
    </div>
    <div class="metric">
      <div class="value">{{ "%.1f"|format(state.memory_percent) }}%</div>
      <div class="label">Memory Usage</div>
    </div>
    <div class="metric">
      <div class="value">{{ uptime }}</div>
      <div class="label">Uptime</div>
    </div>
  </div>

  <h2>🚫 Banned IPs</h2>
  {% if state.banned_ips %}
  <table>
    <tr><th>IP</th><th>Unban Time</th></tr>
    {% for ip, unban_time in state.banned_ips.items() %}
    <tr>
      <td class="banned">{{ ip }}</td>
      <td>{{ "PERMANENT" if unban_time == -1 else unban_time }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p class="safe">No IPs currently banned ✓</p>
  {% endif %}

  <h2>🔥 Top 10 Source IPs</h2>
  <table>
    <tr><th>IP</th><th>Requests (last 60s)</th></tr>
    {% for ip, count in state.top_ips %}
    <tr><td>{{ ip }}</td><td>{{ count }}</td></tr>
    {% endfor %}
  </table>

  <p style="color:#8b949e; font-size:0.8em;">
    Auto-refreshes every 3 seconds | 
    Last update: {{ now }}
  </p>
</body>
</html>
"""


@app.route("/")
def index():
    uptime_secs = int(time.time() - state["uptime_start"])
    hours, rem = divmod(uptime_secs, 3600)
    minutes, seconds = divmod(rem, 60)
    uptime = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    state["cpu_percent"] = psutil.cpu_percent()
    state["memory_percent"] = psutil.virtual_memory().percent

    return render_template_string(
        TEMPLATE,
        state=state,
        uptime=uptime,
        now=time.strftime("%Y-%m-%d %H:%M:%S")
    )


def update_state(new_state):
    """Called from main loop to update dashboard data."""
    state.update(new_state)


def start(port=8080):
    """Start dashboard in background thread."""
    thread = threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=port, debug=False),
        daemon=True
    )
    thread.start()
    print(f"[dashboard] Running on port {port}")
