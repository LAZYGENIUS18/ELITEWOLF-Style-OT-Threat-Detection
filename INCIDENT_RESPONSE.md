# ICS/OT Incident Response Playbook
## ELITEWOLF-Style Threat Detection Lab

---

## ICS IR is Different from IT IR

| Step | IT Incident Response | OT/ICS Incident Response |
|---|---|---|
| Containment | Take system offline immediately | **DO NOT** take offline without ops approval — could cause physical harm |
| Patching | Patch ASAP | Patches require change management, maintenance windows, vendor approval |
| Evidence | Pull disk image | Avoid touching PLC — memory is volatile and overwrite stops the process |
| Priority | Confidentiality | **Safety first**, then availability, then integrity |
| Who leads | CISO / IT Security | Plant manager + Safety officer + ICS security analyst |

---

## Playbook: Unauthorized Modbus Write Commands

### Trigger
IDS Rule: `OT-MODBUS Write Multiple Coils` (SID 9000005)

### Severity: CRITICAL

---

### Phase 1 — Detection & Initial Triage (0–15 min)

```
□ Confirm alert is not a false positive
  - Is the source IP an authorized engineering workstation?
  - Is this during a scheduled maintenance window?
  - Did an operator initiate this change via HMI?

□ Identify source
  - SIEM query: index=ot_traffic | search src_ip=<ALERT_IP>
  - Check asset inventory — is this a known device?
  - Check DHCP logs for MAC address of source

□ Identify target
  - Which PLC / which coil addresses were written?
  - What do those coils control physically? (check P&ID diagrams)
  - Are there safety interlocks on those coils?

□ Notify
  - ICS Operations Lead (for physical situational awareness)
  - SOC Manager
  - Plant Safety Officer if safety coils were touched
```

### Phase 2 — Containment (15–45 min)

```
□ DO NOT shut down the PLC without operations approval

□ Network isolation options (least to most disruptive):
  1. ACL on switch port — block source IP at Layer 2
  2. Firewall rule — block source IP at DMZ boundary
  3. VLAN reassignment — move attacker port to quarantine VLAN
  4. Physical disconnect — pull cable from attacker device

□ Capture evidence BEFORE isolation if possible:
  - Full PCAP of session (if span port active)
  - Netflow records from that segment
  - Switch port logs (MAC, VLAN, timestamps)
  - PLC audit log / event log export

□ Verify PLC physical state with operations team:
  - Are all outputs in expected state?
  - Has any process variable deviated?
  - Is any safety interlock in unexpected state?
```

### Phase 3 — Eradication & Recovery (45 min – 4 hrs)

```
□ Remove attacker from network
□ Reset PLC to known-good state from backup (with ops approval)
□ Verify PLC logic has not been modified (compare checksums)
□ Change any default credentials on PLC if applicable
□ Review firewall rules — how did attacker reach Level 1?
□ Check for persistence (new accounts, scheduled tasks on HMIs)
```

### Phase 4 — Post-Incident (24–72 hrs)

```
□ Write Incident Report (use lab's report generator)
□ Map to MITRE ATT&CK for ICS
□ Submit to CISA if critical infrastructure affected
□ Lessons learned meeting with ops + security
□ Update IDS rules if detection gaps found
□ Consider network segmentation improvements
```

---

## Playbook: IT-to-OT Lateral Movement

### Trigger
IDS Rule: `OT-ENIP IT-to-OT Lateral Movement`

### Key Questions
1. What enterprise asset initiated the connection?
2. Was the Jump Server / bastion host bypassed?
3. What credentials were used?
4. What did the attacker do once in OT?

### Containment Priority
Block at DMZ firewall — enterprise IPs should never directly reach OT Level 1/2 without the jump server.

---

## Evidence Checklist

```
□ IDS alert logs with timestamps (export from lab)
□ PCAP file of suspicious session
□ Netflow/connection logs
□ SIEM query results (save SPL + output)
□ PLC audit log
□ Asset inventory snapshot
□ DHCP / ARP tables at time of incident
□ Firewall logs
□ HMI operator session logs
```

---

## CISA Reporting

If you work at critical infrastructure (energy, water, transportation), serious ICS incidents should be reported:

- **CISA 24/7 Hotline:** 888-282-0870
- **Email:** report@cisa.gov
- **Online:** https://www.cisa.gov/forms/report

---

## References

- NIST SP 800-82 Rev.3 — Guide to OT Security
- ICS-CERT IR Procedures: https://www.cisa.gov/ics-cert
- SANS ICS Curriculum: https://ics.sans.org
- Dragos IR Services: https://www.dragos.com/services/
