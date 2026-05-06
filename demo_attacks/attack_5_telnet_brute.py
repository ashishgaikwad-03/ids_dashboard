"""
ATTACK 5: Telnet Brute Force — Credential Stuffing
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Simulates an attacker attempting default credentials on IoT devices
via Telnet (port 23). Common Mirai botnet recruitment technique.

Detection : Telnet-Brute (severity 82)
Telegram  : ✅ Triggered automatically
Dashboard : ✅ Real-time via WebSocket

Run: python attack_5_telnet_brute.py
"""
import requests, time, random

API = "http://localhost:8000"
ESP32_IP = "192.168.166.167"

ATTACKER_IP = "198.51.100.77"
IOT_DEVICES = [
    {"ip": ESP32_IP,       "name": "ESP32-CAM"},
    {"ip": "192.168.1.10", "name": "IP Camera"},
    {"ip": "192.168.1.20", "name": "Smart Router"},
    {"ip": "192.168.1.30", "name": "NVR Recorder"},
]

CREDENTIALS = [
    "admin:admin", "root:root", "admin:1234", "root:password",
    "admin:password", "user:user", "root:toor", "admin:default",
    "admin:12345", "root:admin",
]
ATTEMPTS_PER_DEVICE = 8
TOTAL = len(IOT_DEVICES) * ATTEMPTS_PER_DEVICE

print("=" * 65)
print("  🔓 ATTACK 5: TELNET BRUTE FORCE — CREDENTIAL STUFFING")
print(f"  Attacker       : {ATTACKER_IP}")
print(f"  Target Devices : {len(IOT_DEVICES)}")
print(f"  Attempts/Device: {ATTEMPTS_PER_DEVICE}")
print(f"  Total Attempts : {TOTAL}")
print("=" * 65)

count = 0
for device in IOT_DEVICES:
    print(f"\n  >> Attacking {device['name']} ({device['ip']}:23)")
    for i in range(ATTEMPTS_PER_DEVICE):
        count += 1
        cred = CREDENTIALS[i % len(CREDENTIALS)]
        try:
            r = requests.post(f"{API}/api/inject-attack", params={
                "attack_type": "brute",
                "source_ip": ATTACKER_IP,
                "dest_ip": device["ip"],
            })
            data = r.json()
            print(f"  [{count:03d}/{TOTAL}] 🟠 {data['classification']} | Trying '{cred}' on {device['name']}")
        except Exception as e:
            print(f"  [{count:03d}] FAILED: {e}")
        time.sleep(random.uniform(0.15, 0.4))

print(f"\n{'=' * 65}")
print(f"  ✅ Brute force complete. {count} login attempts.")
print(f"  → Check Dashboard + Telegram for Telnet-Brute alerts!")
print(f"{'=' * 65}")
