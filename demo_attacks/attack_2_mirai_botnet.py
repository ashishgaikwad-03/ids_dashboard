"""
ATTACK 2: Mirai Botnet ACK Flood
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Simulates compromised IoT devices (cameras, thermostats, routers)
launching coordinated ACK flood waves against the network gateway.

Detection : Mirai-ACK (severity 85)
Telegram  : ✅ Triggered automatically
Dashboard : ✅ Real-time via WebSocket

Run: python attack_2_mirai_botnet.py
"""
import requests, time, random

API = "http://localhost:8000"
ESP32_IP = "192.168.166.167"

BOTNET = [
    {"ip": "10.0.0.55",     "name": "IoT Camera #1"},
    {"ip": "10.0.0.112",    "name": "Smart Thermostat"},
    {"ip": "172.16.5.88",   "name": "NAS Drive"},
    {"ip": "10.0.0.201",    "name": "IP Doorbell"},
    {"ip": "192.168.2.77",  "name": "Smart TV"},
    {"ip": "10.0.0.33",     "name": "WiFi Extender"},
    {"ip": "172.16.5.144",  "name": "Baby Monitor"},
]
WAVES = 4
TOTAL = len(BOTNET) * WAVES

print("=" * 65)
print("  🤖 ATTACK 2: MIRAI BOTNET ACK FLOOD")
print(f"  Compromised Bots : {len(BOTNET)} IoT devices")
print(f"  Attack Waves     : {WAVES}")
print(f"  Total Packets    : {TOTAL}")
print("=" * 65)

count = 0
for wave in range(1, WAVES + 1):
    print(f"\n  ── Wave {wave}/{WAVES} ──")
    for bot in BOTNET:
        count += 1
        try:
            r = requests.post(f"{API}/api/inject-attack", params={
                "attack_type": "ddos",
                "source_ip": bot["ip"],
                "dest_ip": ESP32_IP,
            })
            data = r.json()
            print(f"  [{count:03d}/{TOTAL}] 🔴 {data['classification']} | {bot['name']} ({bot['ip']})")
        except Exception as e:
            print(f"  [{count:03d}] FAILED: {e}")
        time.sleep(random.uniform(0.08, 0.2))
    time.sleep(0.3)

# Report camera disruption
requests.post(f"{API}/api/esp32/camera-status", json={
    "status": "FROZEN", "target_ip": ESP32_IP
})
print("\n  [CAM] ❄️  Camera FROZEN — Botnet DDoS saturated the network!")

print(f"\n{'=' * 65}")
print(f"  ✅ Botnet attack complete. {count} packets from {len(BOTNET)} bots.")
print(f"  → Check Dashboard + Telegram for Mirai-ACK alerts!")
print(f"{'=' * 65}")
