# ⚡ ELITEWOLF-Style OT Threat Detection Lab
### Student Edition — Hands-On ICS/OT Security Monitoring Platform

![License](https://img.shields.io/badge/license-MIT-green)
![HTML](https://img.shields.io/badge/built%20with-HTML%2FJS-blue)
![OT Security](https://img.shields.io/badge/domain-OT%2FICS%20Security-red)
![MITRE](https://img.shields.io/badge/framework-MITRE%20ATT%26CK%20ICS-orange)
![CISA](https://img.shields.io/badge/reference-CISA%20ELITEWOLF-yellow)

---

## 📌 Project Overview

A fully browser-based **OT/ICS Security Operations Center (SOC) simulator** inspired by the NSA/CISA [ELITEWOLF](https://github.com/nsacyber/ELITEWOLF) IDS signature repository. Built to develop and demonstrate hands-on skills in industrial cybersecurity — covering threat detection, IDS rule engineering, SIEM hunting, protocol analysis, and incident response.

> **No installation required.** Open `index.html` in any modern browser.

---

## 🎯 Skills Demonstrated

| Skill | Tool/Concept |
|---|---|
| OT Protocol Analysis | Modbus, DNP3, EtherNet/IP, S7Comm, OPC-UA |
| IDS Rule Engineering | Snort-compatible signatures (ELITEWOLF-style) |
| Threat Detection | Anomaly detection, signature matching |
| SIEM Threat Hunting | SPL query language (Splunk-style) |
| MITRE ATT&CK for ICS | Technique mapping, coverage heatmap |
| Incident Response | Professional IR report generation |
| Network Architecture | Purdue Reference Model (ISA-99) |
| Asset Management | OT device inventory and classification |

---

## 🖥️ Features

### 9 Fully Interactive Modules

```
┌─────────────────────────────────────────────────────────┐
│  1. Dashboard      — Live SOC overview, Purdue topology  │
│  2. Alert Queue    — Triage, filter, investigate alerts  │
│  3. Packet Analysis— PCAP viewer + protocol decoder      │
│  4. IDS Rules      — Snort rule editor, live rule engine │
│  5. Asset Inventory— OT device registry with risk status │
│  6. MITRE ATT&CK   — ICS coverage heatmap               │
│  7. SIEM / Hunt    — SPL query console + visualizations  │
│  8. Incident Report— IR document generator               │
│  9. Attack Sim     — 6 injectable OT attack scenarios    │
└─────────────────────────────────────────────────────────┘
```

### Attack Scenarios (Simulated / Safe)

| Scenario | MITRE Technique | Real-World Reference |
|---|---|---|
| Modbus Reconnaissance | T0888 Remote System Info | Pre-attack recon |
| Unauthorized Coil Write | T0836, T0855 | INCONTROLLER / PIPEDREAM |
| DNP3 Warm Restart | T0813, T0815 | CRASHOVERRIDE / Industroyer |
| S7comm CPU Stop | T0816 | Stuxnet |
| IT→OT Lateral Movement | T0866, T0859 | Colonial Pipeline pattern |
| EtherNet/IP Config Tamper | T0836 | Trisis/Triton-style |

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ot-threat-lab.git

# Open in browser — no server, no install needed
cd ot-threat-lab
open index.html        # macOS
start index.html       # Windows
xdg-open index.html    # Linux
```

Or just **[click here to try the live demo →](https://YOUR_USERNAME.github.io/ot-threat-lab)**

---

## 📁 Repository Structure

```
ot-threat-lab/
│
├── index.html                  # Main application (single-file lab)
│
├── rules/
│   ├── modbus_detection.rules  # Snort rules — Modbus attacks
│   ├── dnp3_detection.rules    # Snort rules — DNP3 attacks
│   ├── enip_detection.rules    # Snort rules — EtherNet/IP attacks
│   └── s7comm_detection.rules  # Snort rules — S7comm / Siemens
│
├── scripts/
│   ├── simulate_traffic.py     # Python traffic generator (for Wireshark practice)
│   ├── parse_modbus.py         # Modbus packet parser
│   └── alert_exporter.py       # Export alerts to CSV/JSON
│
├── docs/
│   ├── ARCHITECTURE.md         # Purdue Model explained
│   ├── PROTOCOLS.md            # OT protocol reference guide
│   ├── MITRE_MAPPING.md        # Full ATT&CK for ICS technique list
│   └── INCIDENT_RESPONSE.md    # IR playbook template
│
└── README.md
```

---

## 🔬 OT Protocols Covered

### Modbus TCP (Port 502)
The most common ICS protocol. Function codes monitored:
- `FC 01` Read Coils
- `FC 03` Read Holding Registers
- `FC 05` **Write Single Coil** ← attack vector
- `FC 0F` **Write Multiple Coils** ← INCONTROLLER/PIPEDREAM
- `FC 08` Diagnostics / Force Listen Only Mode

### DNP3 (Port 20000)
Used in electric utilities and water systems:
- `FC 0D` **Warm Restart** ← causes monitoring gap
- `FC 81` Response / Unsolicited
- Direct Operate commands

### EtherNet/IP / CIP (Port 44818)
Allen-Bradley / Rockwell protocol:
- `CIP 0x10` **Set Attribute Single** ← config tamper
- `CIP 0x0E` Get Attribute Single

### S7comm (Port 102)
Siemens SIMATIC protocol:
- `0x29` **Stop CPU** ← Stuxnet technique
- `0x28` Start CPU
- Read/Write SZL

---

## 📋 IDS Rules Reference

All rules follow **Snort 2.9+ syntax** compatible with CISA ELITEWOLF.

### Example: Detect Modbus Write Multiple Coils
```snort
alert tcp any any -> 192.168.10.0/24 502 (
  msg:"OT-MODBUS Write Multiple Coils - Possible Unauthorized Command";
  flow:to_server,established;
  content:"|00 00|"; depth:2;
  content:"|0F|"; offset:7; depth:1;
  classtype:protocol-command-decode;
  priority:1;
  sid:9000002; rev:1;
)
```

### Example: Detect S7comm CPU Stop
```snort
alert tcp any any -> 192.168.10.0/24 102 (
  msg:"OT-S7COMM CPU Stop Command - Critical";
  flow:to_server,established;
  content:"|03 00|"; depth:2;
  content:"|29|"; offset:17; depth:1;
  classtype:attempted-dos;
  priority:1;
  sid:9000007; rev:1;
)
```

### Example: Detect DNP3 Warm Restart
```snort
alert tcp any any -> 192.168.10.0/24 20000 (
  msg:"OT-DNP3 Warm Restart from Unauthorized Source";
  flow:to_server,established;
  content:"|05 64|"; depth:2;
  content:"|0D|"; offset:12; depth:1;
  threshold:type limit,track by_src,count 1,seconds 60;
  priority:1;
  sid:9000008; rev:1;
)
```

---

## 🗡️ MITRE ATT&CK for ICS Coverage

| Tactic | Technique | ID | Detection Status |
|---|---|---|---|
| Impact | Modify Parameter | T0836 | ✅ Detected |
| Impact | Unauthorized Command | T0855 | ✅ Detected |
| Impact | Device Restart/Shutdown | T0816 | ✅ Detected |
| Impact | Denial of Control | T0813 | ✅ Detected |
| Discovery | Network Sniffing | T0840 | ✅ Detected |
| Discovery | Remote System Info | T0888 | 🟡 Partial |
| Lateral Movement | Exploit Remote Services | T0866 | 🟡 Partial |
| Persistence | Module Firmware | T0839 | ❌ Not covered |
| Execution | Change Op Mode | T0858 | 🟡 Partial |

---

## 🎓 Learning Path

**Beginner:** Start with the Dashboard and Attack Simulator. Run each scenario and watch the alerts generate.

**Intermediate:** Go to IDS Rules. Read each existing rule, understand what it detects, then try writing your own using the templates.

**Advanced:** Use the SIEM tab to write SPL threat hunting queries. Try to find patterns in the alert data that the IDS rules missed.

**Portfolio-ready:** Fill in a complete Incident Report after running the "Unauthorized Coil Write" scenario. Save it as a PDF.

---

## 📚 References & Further Reading

| Resource | URL |
|---|---|
| CISA ELITEWOLF (real IDS signatures) | https://github.com/nsacyber/ELITEWOLF |
| MITRE ATT&CK for ICS | https://attack.mitre.org/matrices/ics/ |
| NIST SP 800-82 Rev.3 (ICS Security) | https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final |
| IEC 62443 Standard | https://www.iec.ch/isa99 |
| CISA ICS Advisories | https://www.cisa.gov/ics-advisories |
| Dragos Year in Review | https://www.dragos.com/year-in-review/ |
| Modbus Protocol Spec | https://modbus.org/specs.php |
| DNP3 Overview | https://www.dnp.org |

---

## 🛡️ Disclaimer

> This project is **strictly educational**. All traffic, packets, and attack scenarios are **100% simulated** — no real network traffic is generated. No actual ICS/OT systems are targeted or affected. Built for learning and portfolio demonstration purposes only.

---

## 📄 License

MIT License — free to use, modify, and share with attribution.

---

## 👤 Author

**[LAZYGENIUS18]**
- GitHub: [@LAZYGENIUS18](https://github.com/LAZYGENIUS18)

*Built as a portfolio project for OT/ICS cybersecurity roles.*

---

⭐ **If this helped you, please star the repo!**
