#!/usr/bin/env python3
"""
OT Traffic Simulator — ELITEWOLF-Style Lab
==========================================
Generates synthetic OT/ICS network traffic for Wireshark analysis
and IDS rule testing. Safe for lab environments only.

Usage:
    python simulate_traffic.py --mode normal     # baseline traffic
    python simulate_traffic.py --mode recon      # reconnaissance scan
    python simulate_traffic.py --mode attack     # attack simulation
    python simulate_traffic.py --log alerts.json # log to file

Requirements: pip install scapy pymodbus
"""

import argparse
import json
import random
import time
import datetime
import sys
from dataclasses import dataclass, asdict
from typing import List, Optional

# ── CONFIG ────────────────────────────────────────────────────────────────────

PLC_IPS     = ["192.168.10.5", "192.168.10.6"]
RTU_IPS     = ["192.168.10.20"]
HMI_IPS     = ["192.168.20.10", "192.168.20.12"]
SCADA_IPS   = ["192.168.20.50"]
ENG_IPS     = ["192.168.30.5", "192.168.30.6"]
ATTACKER_IP = "192.168.50.99"

MODBUS_PORT  = 502
DNP3_PORT    = 20000
ENIP_PORT    = 44818
S7COMM_PORT  = 102

# ── DATA CLASSES ──────────────────────────────────────────────────────────────

@dataclass
class OTPacket:
    timestamp:   str
    src_ip:      str
    dst_ip:      str
    src_port:    int
    dst_port:    int
    protocol:    str
    function:    str
    function_code: Optional[int]
    payload_hex: str
    length:      int
    is_suspicious: bool
    alert_msg:   Optional[str]
    mitre_technique: Optional[str]

# ── PACKET GENERATORS ─────────────────────────────────────────────────────────

def ts() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"

def rand_port() -> int:
    return random.randint(49152, 65535)

def hex_bytes(*values) -> str:
    return " ".join(f"{v:02X}" for v in values)


def gen_modbus_read(src: str, dst: str) -> OTPacket:
    """FC 01/03/04 — normal polling"""
    fc = random.choice([0x01, 0x03, 0x04])
    fc_names = {0x01: "Read Coils", 0x03: "Read Holding Registers", 0x04: "Read Input Registers"}
    start_addr = random.randint(0, 255)
    quantity   = random.randint(1, 64)
    payload = hex_bytes(0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
                        0x01, fc,
                        (start_addr >> 8) & 0xFF, start_addr & 0xFF,
                        (quantity >> 8) & 0xFF, quantity & 0xFF)
    return OTPacket(
        timestamp=ts(), src_ip=src, dst_ip=dst,
        src_port=rand_port(), dst_port=MODBUS_PORT,
        protocol="Modbus TCP", function=fc_names[fc], function_code=fc,
        payload_hex=payload, length=66,
        is_suspicious=False, alert_msg=None, mitre_technique=None
    )


def gen_modbus_write_coil(src: str, dst: str) -> OTPacket:
    """FC 05 — Write Single Coil (suspicious if from non-eng source)"""
    coil_addr  = random.randint(1, 255)
    coil_value = 0xFF00  # ON
    payload = hex_bytes(0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
                        0x01, 0x05,
                        (coil_addr >> 8) & 0xFF, coil_addr & 0xFF,
                        0xFF, 0x00)
    suspicious = src not in ENG_IPS
    return OTPacket(
        timestamp=ts(), src_ip=src, dst_ip=dst,
        src_port=rand_port(), dst_port=MODBUS_PORT,
        protocol="Modbus TCP", function="Write Single Coil (FC 05)", function_code=0x05,
        payload_hex=payload, length=66,
        is_suspicious=suspicious,
        alert_msg="OT-MODBUS Write Single Coil - Unauthorized Command" if suspicious else None,
        mitre_technique="T0855" if suspicious else None
    )


def gen_modbus_write_multi_coils(src: str, dst: str) -> OTPacket:
    """FC 0F — Write Multiple Coils (INCONTROLLER pattern)"""
    start = 0x0001
    count = 0x0040  # 64 coils — matches INCONTROLLER signature
    payload = hex_bytes(0x00, 0x01, 0x00, 0x00, 0x00, 0x0F,
                        0x01, 0x0F,
                        0x00, start & 0xFF,
                        0x00, count & 0xFF,
                        0x08,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
    return OTPacket(
        timestamp=ts(), src_ip=src, dst_ip=dst,
        src_port=rand_port(), dst_port=MODBUS_PORT,
        protocol="Modbus TCP", function="Write Multiple Coils (FC 0F)", function_code=0x0F,
        payload_hex=payload, length=78,
        is_suspicious=True,
        alert_msg="OT-MODBUS Write Multiple Coils - INCONTROLLER/PIPEDREAM Pattern",
        mitre_technique="T0836, T0855"
    )


def gen_modbus_force_listen_only(src: str, dst: str) -> OTPacket:
    """FC 08 Sub 04 — Force Listen Only Mode (DoS)"""
    payload = hex_bytes(0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
                        0x01, 0x08, 0x00, 0x04, 0x00, 0x00)
    return OTPacket(
        timestamp=ts(), src_ip=src, dst_ip=dst,
        src_port=rand_port(), dst_port=MODBUS_PORT,
        protocol="Modbus TCP", function="Force Listen Only Mode (FC 08/04)", function_code=0x08,
        payload_hex=payload, length=66,
        is_suspicious=True,
        alert_msg="OT-MODBUS Force Listen Only Mode - Denial of Control",
        mitre_technique="T0813"
    )


def gen_dnp3_poll(src: str, dst: str) -> OTPacket:
    """DNP3 Class 0 poll — normal telemetry"""
    payload = hex_bytes(0x05, 0x64, 0x14, 0xC4, 0x03, 0x00, 0x01, 0x00,
                        0xA5, 0xC6, 0xC0, 0xC1, 0x01, 0x3C, 0x01, 0x06)
    return OTPacket(
        timestamp=ts(), src_ip=src, dst_ip=dst,
        src_port=rand_port(), dst_port=DNP3_PORT,
        protocol="DNP3", function="Class 0 Data Poll", function_code=0x01,
        payload_hex=payload, length=48,
        is_suspicious=False, alert_msg=None, mitre_technique=None
    )


def gen_dnp3_warm_restart(src: str, dst: str) -> OTPacket:
    """DNP3 Warm Restart (FC 0x0D) — CRASHOVERRIDE pattern"""
    payload = hex_bytes(0x05, 0x64, 0x1A, 0xC4, 0x03, 0x00, 0x01, 0x00,
                        0xA5, 0xC6, 0xC0, 0xC1, 0x0D, 0x00, 0x00, 0x00)
    return OTPacket(
        timestamp=ts(), src_ip=src, dst_ip=dst,
        src_port=rand_port(), dst_port=DNP3_PORT,
        protocol="DNP3", function="Warm Restart (FC 0x0D)", function_code=0x0D,
        payload_hex=payload, length=48,
        is_suspicious=True,
        alert_msg="OT-DNP3 Warm Restart - Denial of Control Attack (CRASHOVERRIDE pattern)",
        mitre_technique="T0813, T0816"
    )


def gen_s7_stop(src: str, dst: str) -> OTPacket:
    """S7comm CPU Stop (Stuxnet technique)"""
    payload = hex_bytes(0x03, 0x00, 0x00, 0x21, 0x02, 0xF0, 0x80,
                        0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E,
                        0x00, 0x00, 0x04, 0x01, 0x12, 0x0A, 0x10, 0x02,
                        0x00, 0x01, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00,
                        0x29)
    return OTPacket(
        timestamp=ts(), src_ip=src, dst_ip=dst,
        src_port=rand_port(), dst_port=S7COMM_PORT,
        protocol="S7comm", function="CPU Stop (0x29)", function_code=0x29,
        payload_hex=payload, length=91,
        is_suspicious=True,
        alert_msg="OT-S7COMM CPU Stop Command - STUXNET/Production Halt",
        mitre_technique="T0816"
    )


# ── TRAFFIC SCENARIOS ─────────────────────────────────────────────────────────

def scenario_normal(duration: int = 30) -> List[OTPacket]:
    """Simulate normal OT baseline traffic"""
    packets = []
    end = time.time() + duration
    print(f"[*] Generating NORMAL baseline traffic for {duration}s...")
    while time.time() < end:
        src = random.choice(ENG_IPS + HMI_IPS)
        dst = random.choice(PLC_IPS + RTU_IPS)
        pkt = gen_modbus_read(src, dst)
        packets.append(pkt)
        _print_packet(pkt)
        time.sleep(random.uniform(0.2, 1.0))
    return packets


def scenario_recon(target: str = None) -> List[OTPacket]:
    """Simulate attacker reconnaissance"""
    packets = []
    target = target or PLC_IPS[0]
    print(f"[!] Simulating RECONNAISSANCE from {ATTACKER_IP} → {target}")
    print(f"    MITRE: T0888 Remote System Info Discovery")
    for fc in [0x01, 0x02, 0x03, 0x04]:
        for addr in range(0, 256, 16):
            pkt = gen_modbus_read(ATTACKER_IP, target)
            pkt.function_code = fc
            pkt.is_suspicious = True
            pkt.alert_msg = "OT-MODBUS Rapid Polling - Reconnaissance"
            packets.append(pkt)
            _print_packet(pkt)
            time.sleep(0.05)
    return packets


def scenario_attack() -> List[OTPacket]:
    """Full attack chain — recon → write → DoS"""
    packets = []
    target = PLC_IPS[0]
    print(f"\n[!] ═══ ATTACK SCENARIO: Full ICS Kill Chain ═══")
    print(f"    Attacker: {ATTACKER_IP} → Target: {target}\n")

    # Phase 1: Recon
    print("[Phase 1] Reconnaissance — mapping coil layout")
    for _ in range(10):
        p = gen_modbus_read(ATTACKER_IP, target)
        p.is_suspicious = True
        packets.append(p); _print_packet(p); time.sleep(0.1)

    # Phase 2: Write Coils
    print("\n[Phase 2] INCONTROLLER-style bulk coil write")
    for _ in range(5):
        p = gen_modbus_write_multi_coils(ATTACKER_IP, target)
        packets.append(p); _print_packet(p); time.sleep(0.2)

    # Phase 3: DoS
    print("\n[Phase 3] Force Listen Only Mode — locking out operators")
    p = gen_modbus_force_listen_only(ATTACKER_IP, target)
    packets.append(p); _print_packet(p)

    # Phase 4: DNP3 RTU restart
    print("\n[Phase 4] DNP3 Warm Restart — blind the SCADA")
    p = gen_dnp3_warm_restart(ATTACKER_IP, RTU_IPS[0])
    packets.append(p); _print_packet(p)

    print(f"\n[!] Attack complete. {len(packets)} packets generated.")
    print(f"    Alerts expected: 3 Critical, 1 High, 1 Medium")
    return packets


# ── HELPERS ───────────────────────────────────────────────────────────────────

def _print_packet(p: OTPacket):
    color_red   = "\033[91m"
    color_yellow= "\033[93m"
    color_green = "\033[92m"
    color_cyan  = "\033[96m"
    color_reset = "\033[0m"

    ts_short = p.timestamp[11:19]
    proto = p.protocol.ljust(12)
    direction = f"{p.src_ip} → {p.dst_ip}:{p.dst_port}"

    if p.is_suspicious:
        print(f"{color_red}[ALERT]{color_reset} {ts_short} | {proto} | {direction}")
        print(f"        FC:{hex(p.function_code or 0)} {p.function}")
        if p.alert_msg:
            print(f"        ⚡ {color_red}{p.alert_msg}{color_reset}")
        if p.mitre_technique:
            print(f"        📌 MITRE: {color_yellow}{p.mitre_technique}{color_reset}")
    else:
        print(f"{color_green}[OK]   {color_reset} {ts_short} | {proto} | {direction} | {p.function}")


def save_to_json(packets: List[OTPacket], path: str):
    with open(path, "w") as f:
        json.dump([asdict(p) for p in packets], f, indent=2)
    print(f"\n[*] Saved {len(packets)} packets to {path}")


def print_summary(packets: List[OTPacket]):
    alerts = [p for p in packets if p.is_suspicious]
    protos  = {}
    for p in packets:
        protos[p.protocol] = protos.get(p.protocol, 0) + 1

    print("\n" + "═"*50)
    print("SIMULATION SUMMARY")
    print("═"*50)
    print(f"Total packets   : {len(packets)}")
    print(f"Suspicious pkts : {len(alerts)}")
    print(f"Alert rate      : {len(alerts)/max(len(packets),1)*100:.1f}%")
    print("\nProtocol breakdown:")
    for proto, count in protos.items():
        print(f"  {proto:<20} {count}")
    if alerts:
        print("\nAlerts fired:")
        for a in alerts:
            print(f"  ⚡ {a.alert_msg}")
            print(f"     MITRE: {a.mitre_technique} | {a.src_ip} → {a.dst_ip}")


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="OT/ICS Traffic Simulator — ELITEWOLF-Style Lab"
    )
    parser.add_argument("--mode", choices=["normal", "recon", "attack"], default="attack",
                        help="Traffic scenario to simulate")
    parser.add_argument("--duration", type=int, default=30,
                        help="Duration in seconds (normal mode)")
    parser.add_argument("--log", type=str, default=None,
                        help="Save packets to JSON file")
    args = parser.parse_args()

    print("="*50)
    print("⚡ OT TRAFFIC SIMULATOR — ELITEWOLF-Style Lab")
    print("   Educational Use Only | No Real Traffic")
    print("="*50 + "\n")

    if args.mode == "normal":
        packets = scenario_normal(args.duration)
    elif args.mode == "recon":
        packets = scenario_recon()
    else:
        packets = scenario_attack()

    print_summary(packets)

    if args.log:
        save_to_json(packets, args.log)


if __name__ == "__main__":
    main()
