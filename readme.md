# Sentinel Shadow v3.0

Sentinel Shadow v3.0 is a deception-driven honeypot dashboard built with FastAPI, React, SQLite, Isolation Forest anomaly scoring, tamper-evident audit chaining, Prometheus metrics, and dual-mode telemetry ingestion. Honeypots are decoy systems designed to attract attackers and gather intelligence, and modern dashboards commonly surface attacker sources, incident trends, and event context in real time.

## What it does

The platform exposes believable decoy routes such as fake admin panels, fake metadata endpoints, and fake sensitive files, then captures every interaction as an incident for analysis.

Each captured event is:
- scored using anomaly detection,
- tagged with severity and risk,
- written to SQLite,
- appended to a hash-linked audit chain,
- exposed through a React dashboard and Prometheus metrics.

## Core features

| Feature | Description |
|---|---|
| Live decoy endpoints | Real requests to `/admin`, `/.env`, `/latest/meta-data`, and `/jenkins/script` are captured as `live` incidents. |
| Demo generator | Synthetic traffic populates the dashboard for predictable presentations and testing. |
| Anomaly ML | Isolation Forest scores suspicious behavior based on request patterns and context. |
| Audit chain | Each event is hash-linked for tamper-evident verification, inspired by security event integrity pipelines. |
| Prometheus metrics | Request counts, decoy hits, alerts, and latency are exposed for monitoring. |
| GeoIP enrichment | Source IPs are labeled with country or network class to improve investigation context.|

## Project structure

```text
sentinel-shadow-v3/
├── backend/
│   ├── app/
│   │   └── main.py
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── package.json
│   ├── index.html
│   └── src/
│       ├── App.jsx
│       ├── main.jsx
│       └── styles.css
└── k8s/
    ├── deployment.yaml
    └── ingress.yaml
```

## Run locally

### 1) Backend

Use Python 3.11 or 3.12 so NumPy and scikit-learn install with compatible wheels more reliably on macOS.

```bash
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 2) Frontend

```bash
cd frontend
npm install
npm run dev
```

The dashboard will usually be available at `http://localhost:5173`, while the FastAPI backend runs at `http://localhost:8000`.[13]

## Demo flow

### Synthetic demo mode

Use the **Generate Demo Traffic** button to create simulated attacker events. This mode is useful for reliable demos because the dashboard updates from real backend data while the incident source remains controlled and repeatable.[7][14]

### Live decoy mode

Use the **Trigger Live Decoys** button or hit the decoy routes manually:

```bash
curl http://localhost:8000/admin
curl http://localhost:8000/.env
curl http://localhost:8000/latest/meta-data
curl http://localhost:8000/jenkins/script
```

FastAPI can access request headers and client host information directly from the incoming request object, which enables capture of live telemetry for these decoy routes.

## GeoIP upgrade

The current build can use a lightweight local IP-to-country helper for demo enrichment, or a real GeoLite2/GeoIP pipeline if deployed publicly. Real honeypot dashboards often enrich source IPs with country, ASN, or map views to improve investigation context.

### Simple local helper

Add this helper and import `enrich_geo()` into the backend if needed:

```python
import ipaddress

def enrich_geo(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return "Localhost"
        if addr.is_private:
            return "Private Network"
    except ValueError:
        return "Unknown"

    if ip.startswith("203."):
        return "Singapore"
    if ip.startswith("198."):
        return "Germany"
    if ip.startswith("45."):
        return "Netherlands"
    if ip.startswith("91."):
        return "United States"
    if ip.startswith("185."):
        return "Russia"
    if ip.startswith("103."):
        return "India"
    return "Unknown"
```

### Production-grade GeoIP path

For a stronger build, replace the prefix-based helper with a proper GeoIP database lookup and optionally add ASN enrichment and a map view. Public honeypot dashboards frequently visualize location trends and source concentration across countries or regions.[9][10][17]

## What the dashboard shows

- **Total Events**: all captured honeypot interactions.[3]
- **Live Events**: incidents generated from real decoy-route access.[6]
- **Demo Events**: incidents produced by the simulator for presentations.[7]
- **Critical Alerts**: highest-risk detections based on anomaly score and context.[1]
- **Threat Timeline**: progression of incident risk over time.[18]
- **Top Source IPs**: most active origins by hit count.[9]
- **Hot Decoys**: which bait assets are attracting the most attention.[3]
- **Audit Chain Blocks**: proof that captured events are hash-linked and verifiable.[2]

## Recommended next upgrades

1. Add real GeoIP lookup with ASN and city enrichment for public deployments.[9][10]
2. Replace seeded CVE data with a scheduled NVD sync job for real vulnerability context.[19]
3. Add a world map or country heat list to visualize source concentration.[10][17]
4. Add alert webhooks for Slack, Discord, or email to demonstrate response automation.[20][19]
5. Add session replay or grouped attacker campaign view to strengthen investigation storytelling.[2]

## Judge-ready pitch

Sentinel Shadow v3.0 is a deception-driven cyber defense platform that plants realistic decoys, captures attacker interaction in real time, scores it with anomaly ML, preserves it in a tamper-evident audit chain, and exposes the full picture through a live dashboard. This turns a honeypot from a passive trap into an analyst-facing detection and investigation product.[1][19][3]

## Troubleshooting

### Port already in use

If Uvicorn reports `Address already in use`, a different process is already bound to the port. On macOS, `lsof` and `kill` are common ways to find and release that process.[21][22]

```bash
lsof -i :8000
kill -9 $(lsof -ti:8000) 2>/dev/null
```

### Backend path issue

If `cd backend` or `cd frontend` fails, confirm the actual nested project directory with `pwd` and `ls` first. A mismatch between the shell location and the VS Code explorer path is a common cause of this problem in nested project folders.