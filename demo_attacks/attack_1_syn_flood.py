"""
ATTACK 1: DDoS SYN Flood → ESP32-CAM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Simulates a massive TCP SYN flood from multiple botnets targeting
the ESP32-CAM device. Overwhelms the device causing camera FREEZE.

Detection : DoS-SYN (severity 88)
Telegram  : ✅ Triggered automatically
Dashboard : ✅ Real-time via WebSocket
Camera    : ✅ Reports FROZEN after flood

Run: python attack_1_syn_flood.py
"""
import requests, time, random

API = "http://localhost:8000"
ESP32_IP = "192.168.166.167"

BOTNETS = [
    "185.220.101.34", "91.219.236.18", "45.155.205.99",
    "194.163.44.12", "23.129.64.210", "162.247.74.7",
    "103.75.190.11", "5.188.206.22",
]
PACKETS_PER_BOT = 5
TOTAL = len(BOTNETS) * PACKETS_PER_BOT

print("=" * 65)
print("  ⚡ ATTACK 1: DDoS TCP SYN FLOOD → ESP32-CAM")
print(f"  Target     : ESP32-CAM ({ESP32_IP})")
print(f"  Attackers  : {len(BOTNETS)} spoofed IPs")
print(f"  Packets    : {TOTAL}")
print("=" * 65)

# Phase 1: Camera is STREAMING (normal)
requests.post(f"{API}/api/esp32/camera-status", json={
    "status": "STREAMING", "target_ip": ESP32_IP
})
print("\n  [CAM] Camera status: STREAMING ✅")
time.sleep(1)

# Phase 2: Launch SYN flood
count = 0
for src_ip in BOTNETS:
    for i in range(PACKETS_PER_BOT):
        count += 1
        try:
            r = requests.post(f"{API}/api/inject-attack", params={
                "attack_type": "dos",
                "source_ip": src_ip,
                "dest_ip": ESP32_IP,
            })
            data = r.json()
            print(f"  [{count:03d}/{TOTAL}] 🔴 {data['classification']} | {src_ip} → {ESP32_IP}")
        except Exception as e:
            print(f"  [{count:03d}] FAILED: {e}")
        time.sleep(random.uniform(0.08, 0.2))

# Phase 3: Camera FREEZES due to flood
print("\n  [CAM] ❄️  Camera FROZEN — SYN flood overwhelmed ESP32!")
requests.post(f"{API}/api/esp32/camera-status", json={
    "status": "FROZEN", "target_ip": ESP32_IP
})

print(f"\n{'=' * 65}")
print(f"  ✅ Attack complete. {count} SYN packets sent.")
print(f"  → Check Dashboard + Telegram for DoS-SYN alerts!")
print(f"{'=' * 65}")
