#!/usr/bin/env python3
"""
Alert Exporter & Log Parser — ELITEWOLF-Style Lab
==================================================
Parse OT IDS alerts and export to CSV / JSON / SIEM format.
Simulates what a SOC analyst does when pivoting from raw logs
to structured threat intelligence.

Usage:
    python alert_exporter.py --input alerts.json --format csv
    python alert_exporter.py --input alerts.json --format siem
    python alert_exporter.py --demo                # generate demo alerts
"""

import json
import csv
import sys
import argparse
import datetime
import random
import io
from dataclasses import dataclass, field, asdict
from typing import List, Optional

# ── ALERT SCHEMA ──────────────────────────────────────────────────────────────

@dataclass
class OTAlert:
    alert_id:        str
    timestamp:       str
    severity:        str          # critical / high / medium / low
    rule_name:       str
    rule_sid:        str
    category:        str
    src_ip:          str
    dst_ip:          str
    dst_port:        int
    protocol:        str
    function_code:   Optional[str]
    mitre_tactic:    Optional[str]
    mitre_technique: Optional[str]
    status:          str = "Open"
    analyst_notes:   str = ""
    iocs:            List[str] = field(default_factory=list)


# ── DEMO ALERT GENERATOR ──────────────────────────────────────────────────────

DEMO_ALERTS = [
    {
        "severity": "critical",
        "rule_name": "OT-MODBUS Write Multiple Coils",
        "rule_sid": "9000005",
        "category": "Unauthorized Command",
        "src_ip": "192.168.50.99",
        "dst_ip": "192.168.10.5",
        "dst_port": 502,
        "protocol": "Modbus TCP",
        "function_code": "0x0F",
        "mitre_tactic": "Impact",
        "mitre_technique": "T0836, T0855",
        "iocs": ["192.168.50.99", "FC:0x0F", "coil_range:0x0001-0x0040"],
    },
    {
        "severity": "high",
        "rule_name": "OT-DNP3 Warm Restart",
        "rule_sid": "9001002",
        "category": "Denial of Control",
        "src_ip": "192.168.50.99",
        "dst_ip": "192.168.10.20",
        "dst_port": 20000,
        "protocol": "DNP3",
        "function_code": "0x0D",
        "mitre_tactic": "Impact",
        "mitre_technique": "T0813, T0816",
        "iocs": ["192.168.50.99", "FC:0x0D"],
    },
    {
        "severity": "critical",
        "rule_name": "OT-S7COMM CPU Stop Command",
        "rule_sid": "9003001",
        "category": "Manipulation of Control",
        "src_ip": "192.168.50.99",
        "dst_ip": "192.168.10.6",
        "dst_port": 102,
        "protocol": "S7comm",
        "function_code": "0x29",
        "mitre_tactic": "Impact",
        "mitre_technique": "T0816",
        "iocs": ["192.168.50.99", "FC:0x29", "target:PLC-02"],
    },
    {
        "severity": "medium",
        "rule_name": "OT-MODBUS Rapid Polling",
        "rule_sid": "9000002",
        "category": "Reconnaissance",
        "src_ip": "192.168.50.99",
        "dst_ip": "192.168.10.5",
        "dst_port": 502,
        "protocol": "Modbus TCP",
        "function_code": "0x03",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T0888",
        "iocs": ["192.168.50.99", "rate:147req/min"],
    },
    {
        "severity": "critical",
        "rule_name": "OT-ENIP IT-to-OT Lateral Movement",
        "rule_sid": "9002005",
        "category": "Lateral Movement",
        "src_ip": "10.0.0.55",
        "dst_ip": "192.168.20.12",
        "dst_port": 44818,
        "protocol": "EtherNet/IP",
        "function_code": "CIP_CONNECT",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T0866",
        "iocs": ["10.0.0.55", "dst:HMI-02", "boundary_violation:IT_to_OT"],
    },
]


def generate_demo_alerts(count: int = 10) -> List[OTAlert]:
    alerts = []
    base_time = datetime.datetime.utcnow() - datetime.timedelta(hours=2)

    for i in range(count):
        template = random.choice(DEMO_ALERTS)
        offset   = datetime.timedelta(minutes=random.randint(1, 120))
        ts       = (base_time + offset).strftime("%Y-%m-%dT%H:%M:%SZ")
        alert_id = f"IDS-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{i+1:04d}"

        alerts.append(OTAlert(
            alert_id=alert_id,
            timestamp=ts,
            status=random.choice(["Open", "Open", "Open", "Investigating", "Acknowledged"]),
            **{k: v for k, v in template.items()}
        ))

    alerts.sort(key=lambda a: a.timestamp)
    return alerts


# ── EXPORTERS ─────────────────────────────────────────────────────────────────

def export_csv(alerts: List[OTAlert], output_path: str):
    fields = [
        "alert_id", "timestamp", "severity", "rule_name", "rule_sid",
        "category", "src_ip", "dst_ip", "dst_port", "protocol",
        "function_code", "mitre_tactic", "mitre_technique", "status"
    ]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for a in alerts:
            row = asdict(a)
            row["iocs"] = "; ".join(row["iocs"])
            writer.writerow({k: row.get(k, "") for k in fields})
    print(f"[✓] CSV exported → {output_path} ({len(alerts)} alerts)")


def export_json(alerts: List[OTAlert], output_path: str):
    with open(output_path, "w") as f:
        json.dump([asdict(a) for a in alerts], f, indent=2)
    print(f"[✓] JSON exported → {output_path} ({len(alerts)} alerts)")


def export_siem_spl(alerts: List[OTAlert]) -> str:
    """Generate Splunk SPL that would recreate this alert dataset"""
    lines = ['| makeresults count=' + str(len(alerts))]
    lines.append('| streamstats count as row_num')
    events = []
    for a in alerts:
        events.append(
            f'if(row_num={alerts.index(a)+1}, "{a.alert_id}", null())'
        )
    output = "Generated SPL Hunt Queries:\n"
    output += "="*50 + "\n\n"
    output += "-- Hunt 1: Find all ICS write commands --\n"
    output += 'index=ot_traffic sourcetype=snort\n'
    output += '| search alert_msg="*Write*" OR alert_msg="*Stop*" OR alert_msg="*Restart*"\n'
    output += '| stats count by src_ip, rule_name, severity\n'
    output += '| where count > 0\n'
    output += '| sort -count\n\n'

    output += "-- Hunt 2: INCONTROLLER/PIPEDREAM pattern --\n"
    output += 'index=ot_traffic sourcetype=modbus\n'
    output += '| where function_code IN ("0x0F","0x05","0x10")\n'
    output += '| bin _time span=1m\n'
    output += '| stats count by _time, src_ip, dst_ip, function_code\n'
    output += '| where count > 20\n\n'

    output += "-- Hunt 3: Lateral movement from enterprise --\n"
    output += 'index=network_traffic\n'
    output += '| where src_subnet="10.0.0.0/8" AND dst_subnet="192.168.0.0/16"\n'
    output += '| where dst_port IN (502,20000,44818,102)\n'
    output += '| stats count, values(dst_ip) as targets by src_ip\n'
    output += '| eval risk=if(count>5,"CRITICAL","HIGH")\n'
    return output


def print_alert_table(alerts: List[OTAlert]):
    SEV_COLOR = {
        "critical": "\033[91m",
        "high":     "\033[93m",
        "medium":   "\033[94m",
        "low":      "\033[96m",
    }
    RESET = "\033[0m"

    print(f"\n{'─'*100}")
    print(f"{'ALERT ID':<25} {'TIME':<22} {'SEV':<10} {'RULE':<40} {'SRC':<16} {'DST':<16}")
    print(f"{'─'*100}")
    for a in alerts:
        c = SEV_COLOR.get(a.severity, "")
        print(f"{c}{a.alert_id:<25} {a.timestamp:<22} {a.severity.upper():<10}{RESET} "
              f"{a.rule_name[:38]:<40} {a.src_ip:<16} {a.dst_ip:<16}")
    print(f"{'─'*100}")

    counts = {}
    for a in alerts:
        counts[a.severity] = counts.get(a.severity, 0) + 1

    print(f"\nSummary: {len(alerts)} total alerts")
    for sev in ["critical", "high", "medium", "low"]:
        if sev in counts:
            c = SEV_COLOR.get(sev, "")
            print(f"  {c}{sev.upper():<10}{RESET}: {counts[sev]}")


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OT Alert Exporter")
    parser.add_argument("--demo",   action="store_true", help="Generate demo alerts")
    parser.add_argument("--input",  type=str, help="Input JSON alert file")
    parser.add_argument("--format", choices=["csv","json","siem","table"], default="table")
    parser.add_argument("--output", type=str, default="ot_alerts_export")
    parser.add_argument("--count",  type=int, default=10, help="Demo alert count")
    args = parser.parse_args()

    if args.demo:
        print(f"[*] Generating {args.count} demo OT alerts...")
        alerts = generate_demo_alerts(args.count)
    elif args.input:
        with open(args.input) as f:
            raw = json.load(f)
        alerts = [OTAlert(**a) for a in raw]
        print(f"[*] Loaded {len(alerts)} alerts from {args.input}")
    else:
        print("Usage: python alert_exporter.py --demo  OR  --input alerts.json")
        sys.exit(1)

    if args.format == "csv":
        export_csv(alerts, f"{args.output}.csv")
    elif args.format == "json":
        export_json(alerts, f"{args.output}.json")
    elif args.format == "siem":
        print(export_siem_spl(alerts))
    else:
        print_alert_table(alerts)


if __name__ == "__main__":
    main()
