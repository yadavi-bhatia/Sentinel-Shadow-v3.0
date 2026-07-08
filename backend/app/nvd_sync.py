from __future__ import annotations
import os
import sqlite3
import requests

DB_PATH = os.getenv("DB_PATH", "sentinel_shadow_v3.db")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

PRODUCT_QUERIES = [
    "nginx",
    "apache http server",
    "jenkins",
    "grafana",
    "openssh",
]


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_table():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product TEXT NOT NULL,
            version TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            score REAL NOT NULL,
            summary TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def extract_metric(metrics: dict):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        vals = metrics.get(key)
        if vals:
            item = vals[0]
            data = item.get("cvssData", {})
            severity = item.get("baseSeverity", data.get("baseSeverity", "unknown"))
            score = float(data.get("baseScore", 0.0))
            return severity.lower(), score
    return "unknown", 0.0


def sync_nvd():
    ensure_table()
    conn = get_conn()
    cur = conn.cursor()
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    for keyword in PRODUCT_QUERIES:
        params = {"keywordSearch": keyword, "resultsPerPage": 20}
        resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])

        cur.execute(
            "DELETE FROM cves WHERE lower(product)=lower(?)", (keyword.split()[0],)
        )

        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "unknown")
            descs = cve.get("descriptions", [])
            summary = next(
                (d.get("value", "") for d in descs if d.get("lang") == "en"), ""
            )[:500]
            severity, score = extract_metric(cve.get("metrics", {}))
            cur.execute(
                """
                INSERT INTO cves (product, version, cve_id, severity, score, summary)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (keyword.split()[0], "unknown", cve_id, severity, score, summary),
            )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    sync_nvd()