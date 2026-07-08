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

The dashboard will usually be available at `http://localhost:5173`, while the FastAPI backend runs at `http://localhost:8000`.

## Demo flow

### Synthetic demo mode

Use the **Generate Demo Traffic** button to create simulated attacker events. This mode is useful for reliable demos because the dashboard updates from real backend data while the incident source remains controlled and repeatable.

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


## What the dashboard shows

- **Total Events**: all captured honeypot interactions.
- **Live Events**: incidents generated from real decoy-route access.
- **Demo Events**: incidents produced by the simulator for presentations.
- **Critical Alerts**: highest-risk detections based on anomaly score and context.
- **Threat Timeline**: progression of incident risk over time.
- **Top Source IPs**: most active origins by hit count.
- **Hot Decoys**: which bait assets are attracting the most attention.
- **Audit Chain Blocks**: proof that captured events are hash-linked and verifiable.

## Explanation of each tech used : 

-**FastAPI**: Python web framework used to build fast backend APIs and decoy routes.

-**React**: Frontend library used to build the live dashboard interface.

-**SQLite**: Lightweight database used to store incidents, campaigns, and audit history.

-**scikit-learn**: Machine learning library used for anomaly detection with Isolation Forest.

-**Isolation Forest**: ML algorithm used to score unusual attacker behavior.

-**Prometheus client**: Exposes backend metrics so system activity can be monitored.

-**GeoIP2 / MaxMind**: Used to map attacker IPs to country, city, ASN, and coordinates.

-**NVD API**: Pulls real vulnerability data so detected services can be tied to known CVEs.

-**Discord / Slack webhooks**: Send instant alerts when high-risk activity is detected.

-**Chart.js**: Renders dashboard charts for risk, source activity, and traffic split.

-**CORS**: Allows the frontend to talk to the backend safely during development.

-**UUIDs**: Create unique session identifiers for grouping attacker activity.

-**Hashing / SHA-256**: Used to build a tamper-evident audit chain.

-**Webhooks**: Let the system push alerts to external chat tools automatically.

-**REST API**: The backend design style used for clean route-based communication.

-**CSS Grid / Flexbox**: Used to create the responsive dashboard layout.

-**JavaScript / JSX**: Powers the interactive React UI components.

