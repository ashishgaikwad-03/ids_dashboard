"""
ATTACK 4: Man-in-the-Middle ARP Spoofing
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Simulates ARP cache poisoning — attacker positions themselves between
the ESP32-CAM and the gateway to intercept all traffic. CRITICAL severity.

Detection : MITM-ARP (severity 92) — HIGHEST!
Telegram  : ✅ Triggered automatically
Dashboard : ✅ Real-time via WebSocket
Camera    : ✅ Reports DOWN (connection hijacked)

Run: python attack_4_mitm_arp.py
"""
import requests, time, random

API = "http://localhost:8000"
ESP32_IP = "192.168.166.167"

ATTACKER_IP = "192.168.1.66"
GATEWAY_IP = "192.168.1.1"
VICTIMS = [ESP32_IP, "192.168.1.10", "192.168.1.20", "192.168.1.50"]
POISON_ROUNDS = 4
TOTAL = len(VICTIMS) * POISON_ROUNDS * 2  # 2 packets per victim per round

print("=" * 65)
print("  🕵️ ATTACK 4: MITM ARP SPOOFING — CRITICAL")
print(f"  Attacker      : {ATTACKER_IP}")
print(f"  Gateway       : {GATEWAY_IP}")
print(f"  Victims       : {len(VICTIMS)} (incl. ESP32-CAM)")
print(f"  Poison Rounds : {POISON_ROUNDS}")
print(f"  Total Packets : {TOTAL}")
print("=" * 65)

count = 0
for rnd in range(1, POISON_ROUNDS + 1):
    print(f"\n  ── ARP Poison Round {rnd}/{POISON_ROUNDS} ──")
    for victim in VICTIMS:
        device = "ESP32-CAM" if victim == ESP32_IP else victim

        # Poison victim → pretend to be gateway
        count += 1
        try:
            r = requests.post(f"{API}/api/inject-attack", params={
                "attack_type": "theft",
                "source_ip": ATTACKER_IP,
                "dest_ip": victim,
            })
            data = r.json()
            print(f"  [{count:03d}/{TOTAL}] 🔴 {data['classification']} | Poisoning {device} (fake gateway)")
        except Exception as e:
            print(f"  [{count:03d}] FAILED: {e}")
        time.sleep(random.uniform(0.08, 0.15))

        # Poison gateway → pretend to be victim
        count += 1
        try:
            r = requests.post(f"{API}/api/inject-attack", params={
                "attack_type": "theft",
                "source_ip": ATTACKER_IP,
                "dest_ip": GATEWAY_IP,
            })
            data = r.json()
            print(f"  [{count:03d}/{TOTAL}] 🔴 {data['classification']} | Poisoning gateway (fake {device})")
        except Exception as e:
            print(f"  [{count:03d}] FAILED: {e}")
        time.sleep(random.uniform(0.08, 0.15))
    time.sleep(0.3)

# Camera goes DOWN — MITM hijacked the connection
print("\n  [CAM] ⛔ Camera DOWN — ARP spoofing hijacked ESP32-CAM connection!")
requests.post(f"{API}/api/esp32/camera-status", json={
    "status": "DOWN", "target_ip": ESP32_IP
})

print(f"\n{'=' * 65}")
print(f"  ✅ ARP Spoofing complete. {count} poison packets sent.")
print(f"  → Check Dashboard + Telegram for MITM-ARP CRITICAL alerts!")
print(f"{'=' * 65}")
