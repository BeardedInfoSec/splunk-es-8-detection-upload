import requests
import urllib3
import yaml
import json
import csv
from urllib.parse import quote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Load creds.yml (shared creds for all servers) ===
with open("creds.yml", "r") as f:
    creds = yaml.safe_load(f)

USERNAME = creds["username"]
PASSWORD = creds["password"]
PORT = 8089

# === Load servers.csv ===
with open("servers.csv", "r") as f:
    servers = [row["host"] for row in csv.DictReader(f)]

# === Load detections.yml ===
with open("detections.yml", "r") as f:
    detections = yaml.safe_load(f)["detections"]

def create_detection_on_server(host, detection):
    base_url = f"https://{host}:{PORT}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches"
    name = detection["name"]

    print(f"[*] [{host}] Creating detection: {name}")

    # 1️⃣ Create base saved search
    base_payload = {
        "name": name,
        "search": detection["search"],
        "description": detection.get("description", name),
        "cron_schedule": detection.get("cron", "*/5 * * * *"),
        "dispatch.earliest_time": detection.get("earliest", "-24h"),
        "dispatch.latest_time": detection.get("latest", "now"),
        "is_scheduled": "1",
        "alert.track": "1",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert_type": "number of events",
    }
    resp = requests.post(base_url, auth=(USERNAME, PASSWORD), data=base_payload, verify=False)
    if resp.status_code not in (200, 201):
        print(f"[!] [{host}] Failed base creation: {resp.status_code}\n{resp.text}")
        return

    # Convert entities and risks to JSON
    entities_json = json.dumps(detection.get("entities", []))
    risks_json = json.dumps(detection.get("risks", []))

    # 2️⃣ Update detection with ES fields
    update_url = f"{base_url}/{quote(name, safe='')}"
    update_payload = {
        "action.correlationsearch.enabled": "1",
        "action.correlationsearch.detection_type": "ebd",
        "action.correlationsearch.label": name,
        "action.notable": "1",
        "action.notable.param.rule_title": detection.get("title", name),
        "action.notable.param.rule_description": detection.get("description", name),
        "action.notable.param.investigation_type": detection.get("investigation_type", "intermediate_finding"),
        "action.notable.param.security_domain": detection.get("domain", "threat"),
        "action.notable.param.severity": detection.get("severity", "medium"),
        "action.notable.param._entities": entities_json,
        "action.risk": "1",
        "action.risk.param._risk_message": detection.get("risk_message", "API-created risk"),
        "action.risk.param._risk": risks_json,
        "actions": detection.get("actions", "notable, risk"),
        "request.ui_dispatch_app": "SplunkEnterpriseSecuritySuite",
    }

    resp = requests.post(update_url, auth=(USERNAME, PASSWORD), data=update_payload, verify=False)
    if resp.status_code in (200, 201):
        print(f"[+] [{host}] Detection created and updated: {name}")
    else:
        print(f"[!] [{host}] Failed ES update: {resp.status_code}\n{resp.text}")

if __name__ == "__main__":
    for host in servers:
        print(f"\n=== Processing server: {host} ===")
        for det in detections:
            create_detection_on_server(host, det)

    print("\n[✅] Bulk YAML detection creation complete across all servers!")
