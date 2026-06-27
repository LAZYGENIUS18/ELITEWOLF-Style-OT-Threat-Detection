# OT/ICS Protocol Reference Guide
## ELITEWOLF-Style Threat Detection Lab

---

## Modbus TCP (Port 502)

The most widely deployed industrial protocol. Originally serial (RS-485), now runs over TCP. No authentication, no encryption — any device on the network can send commands.

### Function Codes

| Code (Hex) | Name | Direction | Risk |
|---|---|---|---|
| 0x01 | Read Coils | Client→Server | Low — recon |
| 0x02 | Read Discrete Inputs | Client→Server | Low — recon |
| 0x03 | Read Holding Registers | Client→Server | Low — recon |
| 0x04 | Read Input Registers | Client→Server | Low — recon |
| 0x05 | **Write Single Coil** | Client→Server | **HIGH** |
| 0x06 | **Write Single Register** | Client→Server | **HIGH** |
| 0x0F | **Write Multiple Coils** | Client→Server | **CRITICAL** — INCONTROLLER |
| 0x10 | **Write Multiple Registers** | Client→Server | **CRITICAL** |
| 0x08 | Diagnostics | Client→Server | **CRITICAL** — DoS possible |
| 0x08/04 | **Force Listen Only** | Client→Server | **CRITICAL** — locks out operators |

### Packet Structure
```
┌─────────────┬──────────────┬──────────┬────────┬──────────────┐
│ Trans ID    │ Protocol ID  │ Length   │ Unit   │ PDU          │
│ 2 bytes     │ 2 bytes      │ 2 bytes  │ 1 byte │ variable     │
│ (any)       │ (0x0000)     │          │ (0x01) │ FC + data    │
└─────────────┴──────────────┴──────────┴────────┴──────────────┘
```

### Detection Logic
- Whitelist engineering workstation IPs — alert on any other source
- Alert on FC 05/0F/10 from non-whitelisted sources
- Alert on FC 08 subfunction 04 (Force Listen Only) from anyone
- Threshold: >100 requests/minute from single source = reconnaissance

---

## DNP3 (Port 20000 TCP/UDP)

Used in electric utilities, water treatment, and oil/gas. Has basic authentication (SAv5) but often disabled. CRASHOVERRIDE/Industroyer exploited DNP3 directly.

### Function Codes

| Code (Hex) | Name | Risk |
|---|---|---|
| 0x01 | Confirm | Low |
| 0x03 | Direct Operate | **HIGH** — sends actuator commands |
| 0x04 | Direct Operate No Ack | **CRITICAL** |
| 0x0D | **Warm Restart** | **CRITICAL** — causes 45s monitoring gap |
| 0x0E | **Cold Restart** | **CRITICAL** — wipes volatile state |
| 0x81 | Unsolicited Response | Low |

### Packet Structure
```
┌────────────┬────────────────────────────────────────────────┐
│ Start Bytes│ 0x0564 (always identifies DNP3)                │
│ Length     │ 1 byte                                         │
│ Control    │ 1 byte                                         │
│ Dst Addr   │ 2 bytes (RTU address)                         │
│ Src Addr   │ 2 bytes (master address)                      │
│ CRC        │ 2 bytes                                        │
│ App Layer  │ Function code + objects                        │
└────────────┴────────────────────────────────────────────────┘
```

### CRASHOVERRIDE Attack Pattern
1. Connect to RTU on port 20000
2. Send FC 0x0D (Warm Restart)
3. RTU goes offline for ~45 seconds
4. Operators lose visibility during attack
5. Repeat to maintain blackout

---

## EtherNet/IP / CIP (Port 44818)

Allen-Bradley (Rockwell Automation) protocol. Common in automotive and manufacturing. Uses CIP (Common Industrial Protocol) over TCP.

### CIP Service Codes

| Service | Name | Risk |
|---|---|---|
| 0x0E | Get Attribute Single | Low — read |
| 0x10 | **Set Attribute Single** | **HIGH** — config write |
| 0x02 | **Set Attribute All** | **CRITICAL** — bulk config |
| 0x05 | **Reset** | **CRITICAL** — device restart |
| 0x4B | Execute Program | **CRITICAL** |

### Detection Focus
- Monitor for Set Attribute (0x10) from non-engineering sources
- Alert on any Reset (0x05) service
- Baseline connection frequency — alert on anomalies

---

## S7comm (Port 102)

Siemens SIMATIC protocol. Made famous by Stuxnet (2010). No authentication in older versions. S7+ (TIA Portal v16+) has improved security.

### Key Functions

| PDU Type | Function | Risk |
|---|---|---|
| Job (0x01) | Read/Write Memory | Medium |
| Job (0x01) | **CPU Stop (0x29)** | **CRITICAL** — halts PLC execution |
| Job (0x01) | **CPU Start (0x28)** | High |
| Job (0x01) | Upload Block | High — logic exfil |
| Job (0x01) | Download Block | **CRITICAL** — logic modification |

### Stuxnet Relevance
Stuxnet used S7comm to:
1. Upload PLC logic blocks
2. Modify frequency drive parameters
3. Intercept monitoring data (return fake normal values)
4. Hide itself from Step 7 software

---

## OPC-UA (Port 4840)

Modern, secure protocol with built-in authentication and encryption. Still monitor for:
- Excessive Browse requests (asset discovery tools)
- Anonymous connections (authentication disabled)
- New NodeID writes from unknown clients

---

## Protocol Decision Matrix

```
When you see this traffic...          Think about...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Modbus FC 0x0F from unknown IP    →  INCONTROLLER / manual attack
DNP3 FC 0x0D from enterprise net  →  CRASHOVERRIDE pattern
S7comm CPU Stop from anywhere     →  Stuxnet / targeted sabotage
Rapid Modbus polls (>100/min)     →  Nmap, Modscan, recon tool
New IP on port 502/102/20000      →  New attacker device / pivot
IT IP talking to Level 1 directly →  Lateral movement, no proxy
```

---

## References

- Modbus Application Protocol Specification v1.1b3: https://modbus.org/specs.php
- DNP3 Basic4 Subset Specification: https://www.dnp.org
- EtherNet/IP Specification: https://www.odva.org
- Siemens S7comm Protocol Analysis (Wireshark wiki)
- CISA ELITEWOLF: https://github.com/nsacyber/ELITEWOLF
