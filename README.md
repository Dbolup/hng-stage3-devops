# Anomaly Detection Engine

A real-time DDoS/anomaly detection daemon built in Python that monitors HTTP traffic, learns normal behaviour, and automatically blocks malicious IPs using iptables.

## Live Links
- **Metrics Dashboard:** http://dareboluwaji.duckdns.org:8080/
- **Blog Post:** https://dev.to/dbolup/how-i-built-a-real-time-ddos-detection-engine-from-scratch-no-libraries-cheat-sheet-4ec7

---

## Language Choice

**Python** was chosen for this project for the following reasons:

- Built-in `collections.deque` is perfectly suited for sliding window implementation — O(1) append and popleft operations
- `subprocess` module makes calling `iptables` commands straightforward
- `Flask` provides a lightweight dashboard with minimal boilerplate
- `threading` module makes it easy to run the unbanner and dashboard in background threads alongside the main detection loop
- Excellent JSON parsing support via the built-in `json` module — ideal for reading Nginx JSON logs
- Readable syntax makes the detection logic easy to audit and explain

---

## How the Sliding Window Works

The sliding window tracks request rates over the **last 60 seconds** using Python's `deque` (double-ended queue) data structure.

### Structure
- One global `deque` tracking all requests
- One `deque` per IP address tracking that IP's requests
- Each entry in the deque is a **Unix timestamp** of when the request arrived

### How it works
```python
from collections import deque
import time

ip_windows = {}  # {ip: deque of timestamps}

def record(ip):
    now = time.time()
    cutoff = now - 60  # 60 seconds ago

    if ip not in ip_windows:
        ip_windows[ip] = deque()

    ip_windows[ip].append(now)  # add new request to RIGHT end

    # Evict old entries from LEFT end
    while ip_windows[ip] and ip_windows[ip][0] < cutoff:
        ip_windows[ip].popleft()

    # Rate = count of requests still in window / window size
    rate = len(ip_windows[ip]) / 60
    return rate
```

### Eviction Logic
- New requests are appended to the **right** end of the deque
- On every new request, we check the **leftmost** (oldest) entry
- If it is older than 60 seconds, we pop it off the left
- We keep popping until all remaining entries are within the window
- This means the deque always contains only the last 60 seconds of timestamps

### Why deque over a list?
Removing from the left of a regular Python list is O(n) — it shifts every element. A deque does it in O(1) — instant, no matter how large the window gets.

---

## How the Baseline Works

The baseline gives the detector context — it answers the question "is this rate unusual compared to recent history?"

### Window Size
- Tracks per-second request counts over a **rolling 30-minute window**
- Stores `(timestamp, count)` tuples in a deque
- Entries older than 30 minutes are evicted from the left

### Recalculation Interval
- Baseline mean and standard deviation are recalculated **every 60 seconds**
- On each recalculation, all counts in the rolling window are used to compute:
  - `mean = sum(counts) / len(counts)`
  - `stddev = sqrt(sum((x - mean)² for x in counts) / len(counts))`

### Per-Hour Slots
- Counts are also stored in per-hour buckets `{hour: [counts]}`
- If the current hour has **60 or more data points**, the baseline prefers that hour's data over the full 30-minute window
- This handles natural traffic patterns — the system knows 9am is busier than 3am

### Floor Values
To prevent false positives on quiet servers:
```yaml
baseline_floor_mean: 0.5     # minimum mean of 0.5 req/s
baseline_floor_stddev: 0.3   # minimum stddev of 0.3
```
Without floor values, a single request on a quiet server would produce a z-score in the thousands and trigger a false ban.

### Anomaly Decision
An IP is flagged if **either** condition fires first:
1. **Z-score** exceeds 2.0: `(current_rate - mean) / stddev > 2.0`
2. **Rate multiplier** exceeds 3×: `current_rate > mean × 3.0`

---

## Repository Structure

```
hng-stage3-devops/
├── detector/
│   ├── main.py          # Entry point — ties all modules together
│   ├── monitor.py       # Tails nginx log file line by line
│   ├── baseline.py      # Rolling baseline tracker
│   ├── detector.py      # Sliding window anomaly detection
│   ├── blocker.py       # iptables ban/unban management
│   ├── unbanner.py      # Background thread for auto-unban
│   ├── notifier.py      # Slack webhook alerts
│   ├── dashboard.py     # Flask live metrics dashboard
│   ├── config.yaml      # All thresholds and settings
│   ├── Dockerfile
│   └── requirements.txt
├── nginx/
│   └── nginx.conf       # JSON access log + reverse proxy config
├── docs/
│   └── architecture.png
├── screenshots/
│   ├── Tool-running.png
│   ├── Ban-slack.png
│   ├── Unban-slack.png
│   ├── Global-alert-slack.png
│   ├── Iptables-banned.png
│   ├── Audit-log.png
│   └── Baseline-graph.png
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Setup Instructions (AWS EC2 — Fresh VPS)

### Prerequisites
- AWS account
- A domain or subdomain pointing to your EC2 IP (we used DuckDNS — free)
- Slack workspace with an incoming webhook URL

---

### Step 1 — Launch EC2 Instance

1. Go to **AWS Console → EC2 → Launch Instance**
2. Use these settings:

| Setting | Value |
|---------|-------|
| Name | hng-stage3-server |
| OS | Ubuntu Server 24.04 LTS |
| Instance type | t3.small (2 vCPU, 2GB RAM minimum) |
| Key pair | Create new → RSA → .pem format |
| Storage | 20 GB |

3. Under **Network Settings → Edit**, add these inbound rules:

| Type | Port | Source |
|------|------|--------|
| SSH | 22 | My IP |
| HTTP | 80 | Anywhere |
| Custom TCP | 8080 | Anywhere |

4. Click **Launch Instance**

---

### Step 2 — Connect to your EC2

```bash
# On your local machine, secure your key file
chmod 400 hng-stage3-key.pem

# SSH into EC2 (replace with your EC2 public IP)
ssh -i hng-stage3-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
```

---

### Step 3 — Install Dependencies on EC2

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker ubuntu
newgrp docker

# Install Docker Compose plugin, iptables, and git
sudo apt install -y docker-compose-plugin iptables git

# Verify installations
docker --version
docker compose version
git --version
iptables --version
```

---

### Step 4 — Set Up DuckDNS Domain (Free)

1. Go to https://www.duckdns.org and sign in with Google
2. Create a subdomain e.g. `yourname.duckdns.org`
3. Enter your EC2 public IP and click **Update IP**
4. Your dashboard will be accessible at `http://yourname.duckdns.org:8080`

---

### Step 5 — Set Up Slack Webhook

1. Go to https://api.slack.com/apps
2. Click **Create New App → From scratch**
3. Name it `HNG Detector`, select your workspace
4. Click **Incoming Webhooks → toggle On**
5. Click **Add New Webhook to Workspace**
6. Select your alerts channel (e.g. `#hng-alerts`)
7. Copy the webhook URL — looks like:
   `https://hooks.slack.com/services/XXXXX/YYYYY/ZZZZZ`

---

### Step 6 — Clone and Configure

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/hng-stage3-devops
cd hng-stage3-devops

# Create environment file
cat > .env << 'EOF'
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
EOF
```

---

### Step 7 — Start the Full Stack

```bash
# Build and start all containers
docker compose up --build -d

# Verify all containers are running
docker compose ps

# Watch detector logs live
docker compose logs -f detector
```

---

### Step 8 — Verify Successful Startup

A successful startup looks like this:

```
✔ Container nginx        Running
✔ Container nextcloud    Running  
✔ Container detector     Running
```

Detector logs should show:
```
[main] Config loaded
[unbanner] Started background unban checker
[dashboard] Running on port 8080
[main] Starting log monitoring...
[monitor] Now tailing: /var/log/nginx/hng-access.log
* Running on http://0.0.0.0:8080
```

Then verify:
```bash
# Nextcloud accessible via IP
curl http://localhost/

# Dashboard accessible
curl http://localhost:8080/

# Nginx writing JSON logs
tail -f /var/lib/docker/volumes/hng-stage3-devops_HNG-nginx-logs/_data/hng-access.log
```

---

### Step 9 — Test Detection

Send a burst of traffic to trigger the detector:

```bash
# From a separate machine, replace with your EC2 public IP
for i in $(seq 1 500); do
  curl -s http://YOUR_EC2_PUBLIC_IP/ > /dev/null &
done
wait
```

Within 10 seconds you should see:
- A ban alert in your Slack `#hng-alerts` channel
- The IP appear in the Banned IPs section of the dashboard
- An iptables DROP rule: `sudo iptables -L -n`
- An audit log entry: `docker compose exec detector cat /var/log/detector/audit.log`

---

## Configuration

All thresholds live in `detector/config.yaml` — no hardcoded values anywhere:

```yaml
sliding_window_seconds: 60      # Track requests over last 60s
baseline_window_minutes: 30     # Learn from last 30 minutes
baseline_recalc_interval: 60    # Recalculate baseline every 60s
zscore_threshold: 2.0           # Flag if z-score exceeds this
rate_multiplier_threshold: 3.0  # Flag if rate exceeds mean × this
error_surge_multiplier: 3.0     # Tighten thresholds on error surge
baseline_floor_mean: 0.5        # Minimum baseline mean
baseline_floor_stddev: 0.3      # Minimum baseline stddev
ban_schedule:
  - 10       # 1st offence: 10 minutes
  - 30       # 2nd offence: 30 minutes
  - 120      # 3rd offence: 2 hours
  - permanent # 4th offence: permanent
```

---

## Environment Variables

```bash
# .env.example
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

---

## Blog Post

Full write-up explaining how everything works, written for beginners:
https://dev.to/dbolup/how-i-built-a-real-time-ddos-detection-engine-from-scratch-no-libraries-cheat-sheet-4ec7
