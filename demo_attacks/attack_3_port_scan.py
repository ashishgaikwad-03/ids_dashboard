"""
ATTACK 3: Aggressive Port Scanner (Reconnaissance)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Simulates an attacker scanning the network to discover open ports
and services on IoT devices — precursor to exploitation.

Detection : Scan-Port (severity 55)
Telegram  : ✅ Triggered automatically
Dashboard : ✅ Real-time via WebSocket

Run: python attack_3_port_scan.py
"""
import requests, time, random

API = "http://localhost:8000"
ESP32_IP = "192.168.166.167"

SCANNER_IP = "103.75.190.44"
TARGETS = [
    ESP32_IP,
    "192.168.1.1",
    "192.168.1.10",
    "192.168.1.50",
    "192.168.1.100",
]
PROBES_PER_TARGET = 6
TOTAL = len(TARGETS) * PROBES_PER_TARGET

print("=" * 65)
print("  🔍 ATTACK 3: AGGRESSIVE PORT SCANNER")
print(f"  Scanner IP   : {SCANNER_IP}")
print(f"  Targets      : {len(TARGETS)} hosts")
print(f"  Total Probes : {TOTAL}")
print("=" * 65)

count = 0
for target in TARGETS:
    device = "ESP32-CAM" if target == ESP32_IP else target
    print(f"\n  >> Scanning {device}")
    for i in range(PROBES_PER_TARGET):
        count += 1
        try:
            r = requests.post(f"{API}/api/inject-attack", params={
                "attack_type": "scan",
                "source_ip": SCANNER_IP,
                "dest_ip": target,
            })
            data = r.json()
            print(f"  [{count:03d}/{TOTAL}] 🟡 {data['classification']} | Probe → {device}")
        except Exception as e:
            print(f"  [{count:03d}] FAILED: {e}")
        time.sleep(random.uniform(0.15, 0.35))

print(f"\n{'=' * 65}")
print(f"  ✅ Port scan complete. {count} probes across {len(TARGETS)} hosts.")
print(f"  → Check Dashboard + Telegram for Scan-Port alerts!")
print(f"{'=' * 65}")
