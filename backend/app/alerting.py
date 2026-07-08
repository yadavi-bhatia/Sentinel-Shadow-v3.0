from __future__ import annotations
import os
import requests

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
ALERT_MIN_SEVERITY = os.getenv("ALERT_MIN_SEVERITY", "high")

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def should_alert(severity: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(ALERT_MIN_SEVERITY, 3)


def send_discord_alert(event: dict):
    if not DISCORD_WEBHOOK_URL or not should_alert(event.get("severity", "low")):
        return {"sent": False, "channel": "discord"}

    payload = {
        "username": "Sentinel Shadow",
        "embeds": [
            {
                "title": f"{event.get('severity', 'unknown').upper()} honeypot alert",
                "description": f"Decoy `{event.get('decoy_name')}` hit from `{event.get('source_ip')}`",
                "color": 16734296 if event.get("severity") == "critical" else 16760576,
                "fields": [
                    {
                        "name": "Mode",
                        "value": str(event.get("mode", "unknown")),
                        "inline": True,
                    },
                    {
                        "name": "Country",
                        "value": str(event.get("geo_country", "Unknown")),
                        "inline": True,
                    },
                    {
                        "name": "Risk",
                        "value": str(event.get("risk_score", 0)),
                        "inline": True,
                    },
                    {
                        "name": "Path",
                        "value": str(event.get("path", "/")),
                        "inline": False,
                    },
                ],
            }
        ],
    }

    r = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
    return {"sent": r.ok, "channel": "discord", "status": r.status_code}


def send_slack_alert(event: dict):
    if not SLACK_WEBHOOK_URL or not should_alert(event.get("severity", "low")):
        return {"sent": False, "channel": "slack"}

    payload = {
        "text": (
            f"{event.get('severity', 'unknown').upper()} honeypot alert: "
            f"{event.get('decoy_name')} from {event.get('source_ip')} "
            f"({event.get('geo_country', 'Unknown')}) "
            f"risk={event.get('risk_score', 0)}"
        )
    }

    r = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
    return {"sent": r.ok, "channel": "slack", "status": r.status_code}