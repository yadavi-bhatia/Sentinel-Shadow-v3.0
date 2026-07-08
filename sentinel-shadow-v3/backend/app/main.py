from __future__ import annotations

from fastapi import FastAPI, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timezone
from typing import Optional, Dict
import hashlib
import json
import os
import random
import sqlite3
import uuid

import numpy as np
from sklearn.ensemble import IsolationForest
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST

from app.geoip_helper import enrich_geo
from app.alerting import send_discord_alert, send_slack_alert

DB_PATH = os.getenv("DB_PATH", "sentinel_shadow_v3.db")
APP_TITLE = "Sentinel Shadow v3"

app = FastAPI(title=APP_TITLE, version="3.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REQ_COUNTER = Counter("sentinel_requests_total", "Incoming requests", ["route", "method"])
ALERT_COUNTER = Counter("sentinel_alerts_total", "Total alerts", ["severity"])
DECOY_HITS = Counter("sentinel_decoy_hits_total", "Decoy hits", ["decoy_type", "name", "mode"])
LAST_SCORE = Gauge("sentinel_last_anomaly_score", "Last anomaly score")
CHAIN_STATUS = Gauge("sentinel_audit_chain_valid", "Audit chain validity")
LATENCY = Histogram("sentinel_request_latency_seconds", "HTTP latency", ["route"])

MODEL_BOOTSTRAP = np.array([
    [1, 0, 200, 0, 0, 14, 0],
    [1, 0, 200, 1, 0, 18, 0],
    [1, 1, 401, 0, 1, 20, 1],
    [2, 0, 200, 0, 0, 10, 0],
    [1, 0, 404, 0, 0, 9, 0],
    [1, 0, 200, 0, 0, 16, 0],
    [2, 1, 403, 2, 1, 25, 2],
    [1, 0, 301, 0, 0, 12, 0],
], dtype=float)
MODEL = IsolationForest(n_estimators=120, contamination=0.10, random_state=42)
MODEL.fit(MODEL_BOOTSTRAP)

DECOYS = [
    {
        "name": "prod-secrets.env",
        "type": "secrets",
        "path": "/.env",
        "lure": "Fake environment secrets with cloud credentials",
        "server": "nginx/1.21.6",
        "sensitivity": 9,
        "service_name": "nginx",
        "service_version": "1.21.6",
    },
    {
        "name": "finance_backup_2026.zip",
        "type": "file",
        "path": "/backup/finance_backup_2026.zip",
        "lure": "Fake finance archive and payroll dump",
        "server": "Apache/2.4.57",
        "sensitivity": 8,
        "service_name": "apache",
        "service_version": "2.4.57",
    },
    {
        "name": "grafana-admin-export.json",
        "type": "admin",
        "path": "/files/grafana-admin-export.json",
        "lure": "Fake admin dashboard export",
        "server": "Grafana/10.0.0",
        "sensitivity": 7,
        "service_name": "grafana",
        "service_version": "10.0.0",
    },
    {
        "name": "k8s_cluster_tokens.txt",
        "type": "k8s",
        "path": "/files/k8s_cluster_tokens.txt",
        "lure": "Fake Kubernetes service account tokens",
        "server": "nginx/1.23.1",
        "sensitivity": 10,
        "service_name": "nginx",
        "service_version": "1.23.1",
    },
    {
        "name": "admin-control",
        "type": "admin",
        "path": "/admin",
        "lure": "Decoy admin login panel",
        "server": "Apache/2.4.57",
        "sensitivity": 8,
        "service_name": "apache",
        "service_version": "2.4.57",
    },
    {
        "name": "jenkins-backup",
        "type": "ci",
        "path": "/jenkins/script",
        "lure": "Decoy Jenkins script console",
        "server": "Jenkins/2.426",
        "sensitivity": 8,
        "service_name": "jenkins",
        "service_version": "2.426",
    },
    {
        "name": "aws-metadata",
        "type": "cloud",
        "path": "/latest/meta-data",
        "lure": "Decoy cloud instance metadata",
        "server": "EC2 metadata",
        "sensitivity": 9,
        "service_name": "openssh",
        "service_version": "8.9",
    },
]
DECOY_MAP = {d["path"]: d for d in DECOYS}

CVE_SEED = [
    ("nginx", "1.21.6", "CVE-2023-44487", "high", 7.5, "HTTP/2 rapid reset denial of service"),
    ("apache", "2.4.57", "CVE-2024-38475", "high", 8.1, "Improper escaping in rewrite scenarios"),
    ("openssh", "8.9", "CVE-2024-6387", "critical", 8.1, "Potential remote code execution race condition"),
    ("grafana", "10.0.0", "CVE-2023-3128", "medium", 6.8, "Issue affecting plugin or auth handling"),
    ("jenkins", "2.426", "CVE-2024-23897", "critical", 9.8, "Arbitrary file read vulnerability"),
]

class EventIn(BaseModel):
    source_ip: str
    method: str
    path: str
    status_code: int
    user_agent: str
    bytes_sent: int = 0
    auth_failed: int = 0
    decoy_type: str = "http"
    decoy_name: str = "unknown"
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    command_count: int = 0
    suspicious_headers: int = 0
    mode: str = "demo"
    session_id: Optional[str] = None
    query_string: Optional[str] = ""
    headers_json: Optional[str] = "{}"
    geo_country: Optional[str] = "Unknown"
    geo_city: Optional[str] = "Unknown"
    asn: Optional[str] = "Unknown"
    asn_org: Optional[str] = "Unknown"
    latitude: Optional[float] = None
    longitude: Optional[float] = None


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        session_id TEXT,
        mode TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        geo_country TEXT,
        geo_city TEXT,
        asn TEXT,
        asn_org TEXT,
        latitude REAL,
        longitude REAL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        query_string TEXT,
        status_code INTEGER NOT NULL,
        user_agent TEXT NOT NULL,
        headers_json TEXT,
        bytes_sent INTEGER NOT NULL,
        auth_failed INTEGER NOT NULL,
        decoy_type TEXT NOT NULL,
        decoy_name TEXT NOT NULL,
        service_name TEXT,
        service_version TEXT,
        command_count INTEGER NOT NULL,
        suspicious_headers INTEGER NOT NULL,
        anomaly_score REAL NOT NULL,
        severity TEXT NOT NULL,
        risk_score REAL NOT NULL,
        alert_sent INTEGER DEFAULT 0
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_chain (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        event_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        block_hash TEXT NOT NULL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product TEXT NOT NULL,
        version TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        score REAL NOT NULL,
        summary TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()


def seed_cves():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM cves")
    if cur.fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO cves (product, version, cve_id, severity, score, summary) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            CVE_SEED,
        )
        conn.commit()
    conn.close()


def append_block(event_type: str, payload: Dict):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT block_hash FROM audit_chain ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    prev_hash = row["block_hash"] if row else "GENESIS"
    ts = now_iso()
    payload_json = json.dumps(payload, sort_keys=True)
    block_hash = sha256_text(f"{ts}|{event_type}|{payload_json}|{prev_hash}")
    cur.execute(
        "INSERT INTO audit_chain (ts, event_type, payload, prev_hash, block_hash) "
        "VALUES (?, ?, ?, ?, ?)",
        (ts, event_type, payload_json, prev_hash, block_hash),
    )
    conn.commit()
    conn.close()
    return block_hash


def verify_chain_internal():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_chain ORDER BY id ASC")
    rows = cur.fetchall()
    conn.close()

    prev_hash = "GENESIS"
    for row in rows:
        expected = sha256_text(
            f"{row['ts']}|{row['event_type']}|{row['payload']}|{prev_hash}"
        )
        if expected != row["block_hash"]:
            CHAIN_STATUS.set(0)
            return {"valid": False, "broken_at": row["id"], "blocks": len(rows)}
        prev_hash = row["block_hash"]
    CHAIN_STATUS.set(1)
    return {"valid": True, "blocks": len(rows)}


def severity_from_score(score: float) -> str:
    if score < -0.12:
        return "critical"
    if score < -0.05:
        return "high"
    if score < 0.02:
        return "medium"
    return "low"


def risk_score(
    score: float,
    sensitivity: int,
    cve_boost: float,
    suspicious_headers: int,
    command_count: int,
):
    anomaly_component = min(max((0.2 - score) * 180, 0), 55)
    sensitivity_component = sensitivity * 3
    cve_component = min(cve_boost * 3, 25)
    header_component = suspicious_headers * 4
    command_component = command_count * 6
    total = (
        anomaly_component
        + sensitivity_component
        + cve_component
        + header_component
        + command_component
    )
    return round(min(total, 100), 2)


def featureize(evt: EventIn):
    path_entropy = min(len(set(evt.path)) / max(len(evt.path), 1), 1.0)
    ua_len = min(len(evt.user_agent or ""), 300)
    return np.array(
        [
            [
                1 if evt.method == "GET" else 2,
                evt.auth_failed,
                evt.status_code,
                int(path_entropy * 10),
                evt.command_count,
                ua_len,
                evt.suspicious_headers,
            ]
        ],
        dtype=float,
    )


def lookup_cves(product: Optional[str], version: Optional[str]):
    if not product:
        return []
    conn = get_conn()
    cur = conn.cursor()
    if version:
        cur.execute(
            """
            SELECT product, version, cve_id, severity, score, summary
            FROM cves
            WHERE lower(product)=lower(?) AND version=?
            ORDER BY score DESC LIMIT 10
            """,
            (product, version),
        )
        rows = [dict(r) for r in cur.fetchall()]
        if rows:
            conn.close()
            return rows
    cur.execute(
        """
        SELECT product, version, cve_id, severity, score, summary
        FROM cves
        WHERE lower(product)=lower(?)
        ORDER BY score DESC LIMIT 10
        """,
        (product,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def store_event(evt: EventIn):
    vec = featureize(evt)
    score = float(MODEL.decision_function(vec)[0])
    severity = severity_from_score(score)
    related_cves = lookup_cves(evt.service_name, evt.service_version)
    cve_boost = max([r["score"] for r in related_cves], default=0.0)
    sensitivity = next(
        (d["sensitivity"] for d in DECOYS if d["name"] == evt.decoy_name), 5
    )
    risk = risk_score(
        score, sensitivity, cve_boost, evt.suspicious_headers, evt.command_count
    )

    LAST_SCORE.set(score)
    ALERT_COUNTER.labels(severity=severity).inc()
    DECOY_HITS.labels(
        decoy_type=evt.decoy_type, name=evt.decoy_name, mode=evt.mode
    ).inc()

    alert_payload = {
        "mode": evt.mode,
        "severity": severity,
        "risk_score": risk,
        "decoy_name": evt.decoy_name,
        "source_ip": evt.source_ip,
        "geo_country": evt.geo_country,
        "path": evt.path,
    }
    discord_result = send_discord_alert(alert_payload)
    slack_result = send_slack_alert(alert_payload)
    alert_sent = int(discord_result.get("sent") or slack_result.get("sent"))

    ts = now_iso()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO events (
            ts, session_id, mode, source_ip, geo_country, geo_city, asn, asn_org, latitude, longitude,
            method, path, query_string, status_code, user_agent, headers_json, bytes_sent,
            auth_failed, decoy_type, decoy_name, service_name, service_version, command_count,
            suspicious_headers, anomaly_score, severity, risk_score, alert_sent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ts,
            evt.session_id,
            evt.mode,
            evt.source_ip,
            evt.geo_country,
            evt.geo_city,
            evt.asn,
            evt.asn_org,
            evt.latitude,
            evt.longitude,
            evt.method,
            evt.path,
            evt.query_string,
            evt.status_code,
            evt.user_agent,
            evt.headers_json,
            evt.bytes_sent,
            evt.auth_failed,
            evt.decoy_type,
            evt.decoy_name,
            evt.service_name,
            evt.service_version,
            evt.command_count,
            evt.suspicious_headers,
            score,
            severity,
            risk,
            alert_sent,
        ),
    )
    conn.commit()
    conn.close()

    payload = evt.dict()
    payload.update(
        {
            "anomaly_score": score,
            "severity": severity,
            "risk_score": risk,
            "cve_count": len(related_cves),
            "alert_sent": alert_sent,
        }
    )
    block_hash = append_block("event_ingested", payload)

    return {
        "status": "ingested",
        "anomaly_score": round(score, 4),
        "severity": severity,
        "risk_score": risk,
        "audit_hash": block_hash,
        "related_cves": related_cves,
        "alert_sent": bool(alert_sent),
    }


def request_to_event(request: Request, decoy: Dict, status_code: int = 200):
    forwarded = request.headers.get("x-forwarded-for")
    source_ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "0.0.0.0")
    )
    user_agent = request.headers.get("user-agent", "unknown")
    headers = {k.lower(): v for k, v in request.headers.items()}
    query_string = str(request.url.query or "")
    suspicious_headers = sum(
        1
        for h in ["x-forwarded-for", "cf-connecting-ip", "x-real-ip"]
        if h in headers
    )
    geo = enrich_geo(source_ip)

    return EventIn(
        source_ip=source_ip,
        method=request.method,
        path=request.url.path,
        status_code=status_code,
        user_agent=user_agent,
        bytes_sent=random.randint(256, 4096),
        auth_failed=1
        if "login" in request.url.path or "admin" in request.url.path
        else 0,
        decoy_type=decoy["type"],
        decoy_name=decoy["name"],
        service_name=decoy.get("service_name"),
        service_version=decoy.get("service_version"),
        command_count=1 if "cmd" in query_string or "exec" in query_string else 0,
        suspicious_headers=suspicious_headers,
        mode="live",
        session_id=str(uuid.uuid4())[:12],
        query_string=query_string,
        headers_json=json.dumps(headers),
        geo_country=geo["country"],
        geo_city=geo["city"],
        asn=geo["asn"],
        asn_org=geo["asn_org"],
        latitude=geo["latitude"],
        longitude=geo["longitude"],
    )


@app.on_event("startup")
def startup_event():
    init_db()
    seed_cves()
    verify_chain_internal()


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    REQ_COUNTER.labels(route=request.url.path, method=request.method).inc()
    with LATENCY.labels(route=request.url.path).time():
        response = await call_next(request)
    return response


@app.get("/")
def root():
    return {"app": APP_TITLE, "status": "ok", "version": "3.1.0"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/decoys")
def list_decoys():
    return {"decoys": DECOYS}


@app.get("/admin")
async def decoy_admin(request: Request):
    evt = request_to_event(request, DECOY_MAP["/admin"], status_code=401)
    result = store_event(evt)
    return {"message": "Unauthorized", "decoy": "admin-control", "result": result}


@app.get("/.env")
async def decoy_env(request: Request):
    evt = request_to_event(request, DECOY_MAP["/.env"], status_code=200)
    result = store_event(evt)
    content = (
        "APP_ENV=prod\n"
        "AWS_SECRET_ACCESS_KEY=decoy-value\n"
        "DB_PASSWORD=shadow-demo\n"
    )
    return Response(content=content, media_type="text/plain")


@app.get("/latest/meta-data")
async def decoy_metadata(request: Request):
    evt = request_to_event(request, DECOY_MAP["/latest/meta-data"], status_code=200)
    result = store_event(evt)
    return {
        "instance-id": "i-decoyshadow123",
        "iam": {"role": "shadow-reader"},
        "result": result,
    }


@app.get("/jenkins/script")
async def decoy_jenkins(request: Request):
    evt = request_to_event(request, DECOY_MAP["/jenkins/script"], status_code=403)
    result = store_event(evt)
    return {"message": "Forbidden", "decoy": "jenkins-backup", "result": result}


@app.get("/backup/finance_backup_2026.zip")
async def decoy_finance_backup(request: Request):
    evt = request_to_event(
        request, DECOY_MAP["/backup/finance_backup_2026.zip"], status_code=200
    )
    store_event(evt)
    return {"message": "archive ready", "note": "decoy artifact"}


@app.get("/files/grafana-admin-export.json")
async def decoy_grafana_export(request: Request):
    evt = request_to_event(
        request, DECOY_MAP["/files/grafana-admin-export.json"], status_code=200
    )
    store_event(evt)
    return {
        "dashboards": [{"uid": "shadow-main", "title": "Prod Overview"}],
        "users": ["admin", "ops-bot"],
    }


@app.get("/files/k8s_cluster_tokens.txt")
async def decoy_k8s_tokens(request: Request):
    evt = request_to_event(
        request, DECOY_MAP["/files/k8s_cluster_tokens.txt"], status_code=200
    )
    store_event(evt)
    content = (
        "default: eyJhbGciOi...decoy\n"
        "ci-bot: eyJhbGciOi...decoy2\n"
    )
    return Response(content=content, media_type="text/plain")


@app.post("/event")
def ingest_event(evt: EventIn):
    return store_event(evt)


@app.post("/demo/generate")
def generate_demo(count: int = 25):
    samples = []
    paths = list(DECOY_MAP.keys())
    sample_ips = [
        "203.0.113.50",
        "198.51.100.24",
        "45.12.33.9",
        "91.240.118.12",
        "185.220.101.4",
        "103.44.12.8",
    ]
    sample_agents = [
        "curl/8.7.1",
        "sqlmap/1.8",
        "python-requests/2.32",
        "Mozilla/5.0",
        "Nmap Scripting Engine",
    ]

    for _ in range(count):
        path = random.choice(paths)
        decoy = DECOY_MAP[path]
        ip = random.choice(sample_ips)
        geo = enrich_geo(ip)
        evt = EventIn(
            source_ip=ip,
            method=random.choice(["GET", "GET", "POST"]),
            path=path,
            status_code=random.choice([200, 401, 403, 404]),
            user_agent=random.choice(sample_agents),
            bytes_sent=random.randint(128, 8192),
            auth_failed=random.choice([0, 1]),
            decoy_type=decoy["type"],
            decoy_name=decoy["name"],
            service_name=decoy.get("service_name"),
            service_version=decoy.get("service_version"),
            command_count=random.choice([0, 0, 1, 2]),
            suspicious_headers=random.choice([0, 1, 2]),
            mode="demo",
            session_id=str(uuid.uuid4())[:12],
            query_string=random.choice(
                ["", "cmd=id", "exec=whoami", "debug=true"]
            ),
            headers_json=json.dumps(
                {
                    "user-agent": random.choice(sample_agents),
                    "x-forwarded-for": ip,
                }
            ),
            geo_country=geo["country"],
            geo_city=geo["city"],
            asn=geo["asn"],
            asn_org=geo["asn_org"],
            latitude=geo["latitude"],
            longitude=geo["longitude"],
        )
        samples.append(store_event(evt))

    return {"generated": len(samples), "results": samples[-5:]}


@app.get("/incidents")
def incidents(limit: int = 50, mode: Optional[str] = None):
    conn = get_conn()
    cur = conn.cursor()
    if mode:
        cur.execute(
            "SELECT * FROM events WHERE mode=? ORDER BY id DESC LIMIT ?",
            (mode, limit),
        )
    else:
        cur.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"incidents": rows}


@app.get("/stats")
def stats():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS total_events FROM events")
    total = cur.fetchone()["total_events"]
    cur.execute("SELECT COUNT(*) AS critical_alerts FROM events WHERE severity='critical'")
    critical = cur.fetchone()["critical_alerts"]
    cur.execute(
        "SELECT ROUND(COALESCE(AVG(risk_score), 0), 2) AS avg_risk_score FROM events"
    )
    avg_risk = cur.fetchone()["avg_risk_score"]
    cur.execute("SELECT COUNT(*) AS live_events FROM events WHERE mode='live'")
    live = cur.fetchone()["live_events"]
    cur.execute("SELECT COUNT(*) AS demo_events FROM events WHERE mode='demo'")
    demo = cur.fetchone()["demo_events"]
    conn.close()
    return {
        "total_events": total,
        "critical_alerts": critical,
        "avg_risk_score": avg_risk,
        "live_events": live,
        "demo_events": demo,
    }


@app.get("/timeline")
def timeline(limit: int = 50):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT ts, risk_score, severity, source_ip, path, decoy_name
        FROM events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"timeline": rows}


@app.get("/sources/top")
def top_sources(limit: int = 10):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT source_ip, COUNT(*) AS hits, MAX(risk_score) AS peak_risk,
               MAX(geo_country) AS geo_country
        FROM events
        GROUP BY source_ip
        ORDER BY hits DESC, peak_risk DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"sources": rows}


@app.get("/decoys/hot")
def hot_decoys(limit: int = 10):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT decoy_name, decoy_type, COUNT(*) AS hits, MAX(risk_score) AS peak_risk
        FROM events
        GROUP BY decoy_name, decoy_type
        ORDER BY hits DESC, peak_risk DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"decoys": rows}


@app.get("/geo/points")
def geo_points(limit: int = 200):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT ts, source_ip, geo_country, geo_city, latitude, longitude,
               severity, risk_score, mode
        FROM events
        WHERE latitude IS NOT NULL AND longitude IS NOT NULL
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"points": rows}


@app.get("/geo/countries")
def geo_countries(limit: int = 20):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT geo_country, COUNT(*) AS hits, MAX(risk_score) AS peak_risk
        FROM events
        GROUP BY geo_country
        ORDER BY hits DESC, peak_risk DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"countries": rows}


@app.get("/campaigns")
def campaigns(limit: int = 20):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT source_ip, geo_country, COUNT(*) AS hits,
               MIN(ts) AS first_seen, MAX(ts) AS last_seen,
               MAX(risk_score) AS peak_risk,
               GROUP_CONCAT(DISTINCT decoy_name) AS decoys
        FROM events
        GROUP BY source_ip, geo_country
        ORDER BY peak_risk DESC, hits DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"campaigns": rows}


@app.get("/replay/{source_ip}")
def replay_source(source_ip: str, limit: int = 50):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT ts, method, path, decoy_name, severity, risk_score, user_agent, mode
        FROM events
        WHERE source_ip=?
        ORDER BY id ASC
        LIMIT ?
        """,
        (source_ip, limit),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"replay": rows}


@app.get("/audit/chain")
def audit_chain(limit: int = 20):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_chain ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"blocks": rows}


@app.get("/audit/verify")
def audit_verify():
    return verify_chain_internal()


@app.get("/cves/{product}")
def cves_by_product(product: str):
    return {"matches": lookup_cves(product, None)}


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)