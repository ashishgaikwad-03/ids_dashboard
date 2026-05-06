import asyncio
import io
import json
import random
import time
import threading
import subprocess
import csv
import uuid
import ipaddress
import pandas as pd
import numpy as np
import joblib
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, File, UploadFile, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import contextlib
import os
from pathlib import Path
from alerts import trigger_alert, get_alert_stats

#  Load Models 
github_model = None
bot_iot_model = None
label_encoder = None
layer2_model = None

try:
    github_model = joblib.load("models/github_xgb_model.joblib")
    print("[IDS]  GitHub XGBoost model loaded (11-class, 99.7% F1)")
except Exception as e:
    print(f"[IDS]  GitHub model not found: {e}")

try:
    esp32_model = joblib.load("models/xgboost_custom_ids.pkl")
    print("[IDS]  ESP32 Custom XGBoost model loaded (Binary, 4-features)")
except Exception as e:
    esp32_model = None
    print(f"[IDS]  ESP32 model not found: {e}")

try:
    bot_iot_model = joblib.load("models/bot_iot_xgb_multiclass.joblib")
    label_encoder = joblib.load("models/label_encoder.joblib")
    layer2_model = joblib.load("models/layer2_anomaly_model.joblib")
    print("[IDS]  Fallback models loaded (BoT-IoT + Layer2)")
except Exception as e:
    print(f"[IDS]  Fallback models: {e}")

# Maps class index ' human-readable label + metadata
GITHUB_LABEL_MAP = {
    0:  {"display": "BENIGN",           "category": "benign",  "severity": 0},
    1:  {"display": "DoS-SYN",          "category": "dos",     "severity": 88},
    2:  {"display": "Mirai-ACK",        "category": "ddos",    "severity": 85},
    3:  {"display": "Host Discovery",   "category": "recon",   "severity": 55},
    4:  {"display": "Telnet-Brute",     "category": "brute",   "severity": 82},
    5:  {"display": "Mirai-HTTP",       "category": "ddos",    "severity": 87},
    6:  {"display": "Mirai-UDP",        "category": "ddos",    "severity": 86},
    7:  {"display": "MITM-ARP",         "category": "mitm",    "severity": 92},
    8:  {"display": "Scan-Host",        "category": "recon",   "severity": 52},
    9:  {"display": "Scan-Port",        "category": "recon",   "severity": 55},
    10: {"display": "Scan-OS",          "category": "recon",   "severity": 58},
}

ESP32_LABEL_MAP = {
    0: {"display": "BENIGN", "category": "benign", "severity": 0},
    1: {"display": "DoS / Flood", "category": "dos", "severity": 88},
}

# Old label mapping for CSV file analysis (BoT-IoT model)
LABEL_MAP = {
    "Normal":            {"display": "BENIGN",      "category": "benign", "severity": 0},
    "TCP":               {"display": "DDoS-TCP",    "category": "ddos",   "severity": 85},
    "UDP":               {"display": "DDoS-UDP",    "category": "ddos",   "severity": 85},
    "HTTP":              {"display": "DoS-HTTP",    "category": "dos",    "severity": 72},
    "OS_Fingerprint":    {"display": "OS SCAN",     "category": "recon",  "severity": 55},
    "Service_Scan":      {"display": "SVC SCAN",    "category": "recon",  "severity": 52},
    "Keylogging":        {"display": "KEYLOG",      "category": "theft",  "severity": 90},
    "Data_Exfiltration": {"display": "DATA EXFIL",  "category": "theft",  "severity": 95},
}

def resolve_label(raw_label: str) -> dict:
    info = LABEL_MAP.get(raw_label, None)
    if info is None:
        return {"display": raw_label.upper(), "category": "unknown", "severity": 60}
    return info

#  The 40 TShark Fields the GitHub Model Expects 
TSHARK_FIELDS = [
    "frame.time_epoch",       # ' timestamp
    "ip.len",                 # ' ip_len
    "ip.id",                  # ' ip_id
    "ip.flags",               # ' ip_flags
    "ip.ttl",                 # ' ip_ttl
    "ip.proto",               # ' ip_proto
    "ip.checksum",            # ' ip_checksum
    "ip.dst",                 # ' ip_dst
    "ip.dst_host",            # ' ip_dst_host
    "tcp.srcport",            # ' tcp_srcport
    "tcp.dstport",            # ' tcp_dstport
    "tcp.port",               # ' tcp_port
    "tcp.stream",             # ' tcp_stream
    "tcp.completeness",       # ' tcp_completeness
    "tcp.seq_raw",            # ' tcp_seq_raw
    "tcp.ack",                # ' tcp_ack
    "tcp.ack_raw",            # ' tcp_ack_raw
    "tcp.flags.reset",        # ' tcp_flags_reset
    "tcp.flags.syn",          # ' tcp_flags_syn
    "tcp.window_size_value",  # ' tcp_window_size_value
    "tcp.window_size",        # ' tcp_window_size
    "tcp.window_size_scalefactor",  # ' tcp_window_size_scalefactor
    "tcp.len",                # ' tcp_ (the column named 'tcp_' in training data)
    "udp.srcport",            # ' udp_srcport
    "udp.dstport",            # ' udp_dstport
    "udp.port",               # ' udp_port
    "udp.length",             # ' udp_length
    "udp.time_delta",         # ' udp_time_delta
    "eth.dst.oui",            # ' eth_dst_oui
    "eth.addr.oui",           # ' eth_addr_oui
    "eth.dst.lg",             # ' eth_dst_lg
    "eth.lg",                 # ' eth_lg
    "eth.ig",                 # ' eth_ig
    "eth.src.oui",            # ' eth_src_oui
    "eth.type",               # ' eth_type
    "icmp.type",              # ' icmp_type
    "icmp.code",              # ' icmp_code
    "icmp.checksum",          # ' icmp_checksum
    "icmp.checksum.status",   # ' icmp_checksum_status
    "arp.opcode",             # ' arp_opcode
]

FEATURE_NAMES = [
    'timestamp', 'ip_len', 'ip_id', 'ip_flags', 'ip_ttl', 'ip_proto',
    'ip_checksum', 'ip_dst', 'ip_dst_host', 'tcp_srcport', 'tcp_dstport',
    'tcp_port', 'tcp_stream', 'tcp_completeness', 'tcp_seq_raw', 'tcp_ack',
    'tcp_ack_raw', 'tcp_flags_reset', 'tcp_flags_syn', 'tcp_window_size_value',
    'tcp_window_size', 'tcp_window_size_scalefactor', 'tcp_', 'udp_srcport',
    'udp_dstport', 'udp_port', 'udp_length', 'udp_time_delta', 'eth_dst_oui',
    'eth_addr_oui', 'eth_dst_lg', 'eth_lg', 'eth_ig', 'eth_src_oui', 'eth_type',
    'icmp_type', 'icmp_code', 'icmp_checksum', 'icmp_checksum_status', 'arp_opcode'
]

#  WebSocket Connection Manager 
class ConnectionManager:
    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead = []
        for conn in self.active_connections:
            try:
                await conn.send_json(message)
            except Exception:
                dead.append(conn)
        for c in dead:
            self.disconnect(c)
        # Trigger desktop/sound/telegram alerts for attacks
        try:
            trigger_alert(message)
        except Exception:
            pass

manager = ConnectionManager()

# 
# TSHARK LIVE CAPTURE ENGINE  Software-Only, No Hardware Required
# 
# How it works:
#   1. TShark (Wireshark CLI) captures packets from your Wi-Fi/Ethernet adapter
#   2. It extracts exactly the 40 fields the GitHub XGBoost model expects
#   3. Each packet's fields are converted to floats (matching training pipeline)
#   4. The XGBoost model classifies each packet into one of 11 categories
#   5. Results are broadcast via WebSocket to the dashboard in real-time
# 

def convert_value_to_float(value: str) -> float:
    """Convert a TShark field value to float, matching the GitHub repo's pipeline."""
    if not value or value == '':
        return -3.0  # NaN substitute (matches training pipeline)
    try:
        # Try direct float conversion
        return float(value)
    except ValueError:
        pass
    try:
        # Hex values (e.g., 0x0800)
        if value.startswith('0x'):
            return float(int(value, 16))
    except (ValueError, TypeError):
        pass
    try:
        # IP address ' integer
        parts = value.split('.')
        if len(parts) == 4:
            ip = ipaddress.ip_address(value)
            return float(int(ip))
    except (ValueError, ipaddress.AddressValueError):
        pass
    # Anything else gets -4 (text value, matches training pipeline)
    return -4.0


class TSharkCapture:
    """
    Live packet capture using TShark subprocess.
    Extracts exactly the 40 features needed by the GitHub XGBoost model.
    Runs entirely in software  no Raspberry Pi or special hardware needed.
    """

    def __init__(self):
        self._process = None
        self._thread = None
        self._loop = None
        self._running = False
        self._interface = None
        self._packet_count = 0
        self._attack_count = 0

    @property
    def is_running(self):
        return self._running

    @property
    def packet_count(self):
        return self._packet_count

    @property
    def attack_count(self):
        return self._attack_count

    def _build_tshark_cmd(self, interface: str) -> list:
        """Build the TShark command with exact field extraction."""
        fields_args = []
        for f in TSHARK_FIELDS:
            fields_args.extend(["-e", f])

        # Add extra display-only fields AFTER the 40 model features
        # 40: ip.src, 41: ipv6.src, 42: ipv6.dst, 43: arp.src.proto_ipv4, 44: arp.dst.proto_ipv4, 45: eth.src
        extra_fields = ["ip.src", "ipv6.src", "ipv6.dst", "arp.src.proto_ipv4", "arp.dst.proto_ipv4", "eth.src", "eth.dst"]
        for f in extra_fields:
            fields_args.extend(["-e", f])

        cmd = [
            "tshark",
            "-i", interface,
            "-l",                    # Line-buffered output for real-time
            "-T", "fields",          # Output as tab-separated fields
            "-E", "separator=,",     # CSV separator
            "-E", "quote=n",         # No quoting
            "-E", "occurrence=f",    # First occurrence only
        ] + fields_args

        return cmd

    def _reader_thread(self):
        """Background thread that reads TShark output line by line."""
        try:
            cmd = self._build_tshark_cmd(self._interface)
            print(f"[IDS] TShark CMD: {' '.join(cmd[:6])}... ({len(TSHARK_FIELDS)} fields)")

            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
            )

            print(f"[IDS]  TShark capture STARTED on interface: {self._interface}")

            for line in self._process.stdout:
                if not self._running:
                    break
                line = line.strip()
                if not line:
                    continue

                # Parse the CSV line into 40 values
                values = line.split(',')
                if len(values) < 40:
                    continue

                # Schedule async processing
                if self._loop and not self._loop.is_closed():
                    asyncio.run_coroutine_threadsafe(
                        self._classify_and_broadcast(values), self._loop
                    )

        except Exception as e:
            print(f"[IDS]  TShark thread error: {e}")
        finally:
            self._running = False
            print("[IDS] TShark reader thread ended")

    async def _classify_and_broadcast(self, raw_values: list):
        """Classify a single packet using the GitHub XGBoost model."""
        try:
            # Convert first 40 values to float (matching the training pipeline)
            features = [convert_value_to_float(v) for v in raw_values[:40]]

            # Extract display-only metadata
            # 40: ip.src, 41: ipv6.src, 42: ipv6.dst, 43: arp.src, 44: arp.dst, 45: eth.src, 46: eth.dst
            # 7: ip.dst is in the main features
            raw_src_ip4 = raw_values[40].strip() if len(raw_values) > 40 else ""
            raw_src_ip6 = raw_values[41].strip() if len(raw_values) > 41 else ""
            raw_dst_ip6 = raw_values[42].strip() if len(raw_values) > 42 else ""
            raw_src_arp = raw_values[43].strip() if len(raw_values) > 43 else ""
            raw_dst_arp = raw_values[44].strip() if len(raw_values) > 44 else ""
            raw_src_eth = raw_values[45].strip() if len(raw_values) > 45 else ""
            raw_dst_eth = raw_values[46].strip() if len(raw_values) > 46 else ""
            
            raw_dst_ip4 = raw_values[7].strip() if len(raw_values) > 7 else ""

            # Resolve best available source and destination
            display_src = raw_src_ip4 or raw_src_ip6 or raw_src_arp or raw_src_eth or "Unknown"
            display_dst = raw_dst_ip4 or raw_dst_ip6 or raw_dst_arp or raw_dst_eth or "Unknown"

            # Determine protocol and port from the raw fields
            tcp_srcport = raw_values[9]   # tcp.srcport
            tcp_dstport = raw_values[10]  # tcp.dstport
            udp_srcport = raw_values[23]  # udp.srcport
            udp_dstport = raw_values[24]  # udp.dstport
            icmp_type = raw_values[35]    # icmp.type
            arp_opcode = raw_values[39]   # arp.opcode

            if tcp_dstport and tcp_dstport != '':
                proto = "TCP"
                port = int(float(tcp_dstport)) if tcp_dstport else 0
            elif udp_dstport and udp_dstport != '':
                proto = "UDP"
                port = int(float(udp_dstport)) if udp_dstport else 0
            elif icmp_type and icmp_type != '':
                proto = "ICMP"
                port = 0
            elif arp_opcode and arp_opcode != '':
                proto = "ARP"
                port = 0
            else:
                proto = "OTHER"
                port = 0

    
            pkt_size = int(features[1]) if features[1] > 0 else 64  # ip.len

            # ------------------------------------------------------------------------------------------------------------------------------------------------------------
            # ML Classification ------------------------------------------------------------------------------------------------------------------------
            label = "BENIGN"
            category = "benign"
            severity = 0
            confidence = 0.95

            if github_model is not None:
                try:
                    feature_array = np.array(features).reshape(1, -1)
                    prediction = int(github_model.predict(feature_array)[0])
                    probas = github_model.predict_proba(feature_array)[0]
                    confidence = float(np.max(probas))

                    info = GITHUB_LABEL_MAP.get(prediction, GITHUB_LABEL_MAP[0])
                    label = info["display"]
                    category = info["category"]
                    severity = info["severity"]
                except Exception as e:
                    # Fallback to benign if model fails on this packet
                    pass

            is_attack = category != "benign"
            self._packet_count += 1
            if is_attack:
                self._attack_count += 1

            # Build and broadcast the payload
            payload = {
                "timestamp":      int(time.time() * 1000),
                "sourceNode":     "TShark-Live",
                "sourceIp":       display_src,
                "destIp":         display_dst,
                "protocol":       proto,
                "port":           port,
                "packetSize":     pkt_size,
                "classification": label,
                "category":       category,
                "severityScore":  int(severity),
                "confidence":     round(confidence, 3),
                "throughputMbps": round(pkt_size * 8 / 1e6, 4),
                "pps":            1,
                "source":         "github_xgb",
            }
            await manager.broadcast(payload)

            if is_attack:
                print(f"[IDS]  {label} ({confidence:.1%}) | {display_src}'{display_dst} [{proto}:{port}]")

        except Exception as e:
            pass  # Skip malformed packets silently

    def start(self, loop: asyncio.AbstractEventLoop, interface: str = None):
        """Start TShark capture on the specified interface."""
        if self._running:
            print("[IDS] Capture already running")
            return

        self._loop = loop
        self._interface = interface or "5"  # Default to Wi-Fi (interface 5)
        self._running = True
        self._packet_count = 0
        self._attack_count = 0

        self._thread = threading.Thread(target=self._reader_thread, daemon=True)
        self._thread.start()
        print(f"[IDS]  Capture started on interface {self._interface}")

    def stop(self):
        """Stop TShark capture."""
        self._running = False
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=3)
            except:
                try:
                    self._process.kill()
                except:
                    pass
            self._process = None
        print("[IDS]  Capture stopped")


capture = TSharkCapture()

# ── ESP32 Device Status Tracker ──────────────────────────────────────────────
esp32_device = {
    "online": False,
    "last_seen": 0,
    "packet_rate": 0.0,
    "byte_rate": 0.0,
    "last_prediction": "BENIGN",
    "last_severity": 0,
    "camera_status": "UNKNOWN",
    "target_ip": "192.168.166.167",
}

#  App Lifecycle 
@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    loop = asyncio.get_event_loop()
    # Auto-start capture on launch
    try:
        capture.start(loop, interface="5")  # Wi-Fi (Realtek RTL8852BE)
    except Exception as e:
        print(f"[IDS] Auto-start failed: {e}")
        print("[IDS] Use POST /api/capture/start to start manually")
    yield
    capture.stop()

app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

#  Health Check 
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "github_model_loaded": github_model is not None,
        "fallback_models_loaded": bot_iot_model is not None,
        "capture_running": capture.is_running,
        "packets_captured": capture.packet_count,
        "attacks_detected": capture.attack_count,
        "ws_clients": len(manager.active_connections),
    }

#  WebSocket 
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

#  Capture Control (Start/Stop) 
@app.post("/api/capture/start")
@app.post("/api/simulation/start")
async def start_capture(interface: str = Query("5", description="TShark interface number")):
    if capture.is_running:
        return {"status": "already_running", "interface": interface}
    loop = asyncio.get_event_loop()
    capture.start(loop, interface=interface)
    return {"status": "started", "interface": interface}

@app.post("/api/capture/stop")
@app.post("/api/simulation/stop")
async def stop_capture():
    if not capture.is_running:
        return {"status": "already_stopped"}
    capture.stop()
    return {"status": "stopped", "packets_captured": capture.packet_count, "attacks_detected": capture.attack_count}

@app.get("/api/capture/status")
async def capture_status():
    return {
        "running": capture.is_running,
        "packets": capture.packet_count,
        "attacks": capture.attack_count,
        "model": "GitHub XGBoost (11-class)" if github_model else "Heuristic Fallback",
    }

#  Alert System Status 
@app.get("/api/alerts")
async def alert_status():
    return get_alert_stats()

#  Attack Injection API (for demo/testing) 
@app.post("/api/inject-attack")
async def inject_attack(
    attack_type: str = Query("ddos", description="ddos, dos, scan, botnet, theft, anomaly"),
    source_ip: str = Query("attacker", description="Source IP"),
    dest_ip: str = Query("192.168.1.1", description="Dest IP"),
):
    configs = {
        "ddos":    {"classification": "Mirai-ACK",     "category": "ddos",  "severity": 85},
        "dos":     {"classification": "DoS-SYN",       "category": "dos",   "severity": 88},
        "scan":    {"classification": "Scan-Port",      "category": "recon", "severity": 55},
        "botnet":  {"classification": "Mirai-UDP",      "category": "ddos",  "severity": 86},
        "theft":   {"classification": "MITM-ARP",       "category": "mitm",  "severity": 92},
        "anomaly": {"classification": "Host Discovery", "category": "recon", "severity": 55},
        "brute":   {"classification": "Telnet-Brute",   "category": "brute", "severity": 82},
    }
    c = configs.get(attack_type.lower(), configs["anomaly"])
    pps = random.randint(100, 3000)
    pkt_size = random.randint(40, 400)
    payload = {
        "timestamp":      int(time.time() * 1000),
        "sourceNode":     "Injected",
        "sourceIp":       source_ip,
        "destIp":         dest_ip,
        "protocol":       "TCP",
        "port":           random.choice([22, 80, 443, 8080, 23]),
        "packetSize":     pkt_size,
        "classification": c["classification"],
        "category":       c["category"],
        "severityScore":  c["severity"],
        "confidence":     round(random.uniform(0.82, 0.97), 3),
        "throughputMbps": round((pkt_size * pps * 8) / 1e6, 4),
        "pps":            pps,
        "source":         "injection",
    }
    await manager.broadcast(payload)
    return {"status": "injected", "classification": c["classification"]}

#  Feature-Level Injection API (runs through ACTUAL XGBoost model) 
from pydantic import BaseModel as PydanticBaseModel
from typing import List

class FeatureInjection(PydanticBaseModel):
    features: List[float]        # Exactly 40 floats matching FEATURE_NAMES order
    source_ip: str = "attacker"
    dest_ip: str = "target"
    protocol: str = "TCP"
    port: int = 0

@app.post("/api/inject-features")
async def inject_features(body: FeatureInjection):
    """Accept a raw 40-feature vector, classify it through the real XGBoost model,
    and broadcast the result to the dashboard. This is how demo scripts trigger
    REAL model-based detection."""
    if github_model is None:
        raise HTTPException(500, "XGBoost model not loaded")
    if len(body.features) != 40:
        raise HTTPException(400, f"Expected 40 features, got {len(body.features)}")

    feature_array = np.array(body.features).reshape(1, -1)
    prediction = int(github_model.predict(feature_array)[0])
    probas = github_model.predict_proba(feature_array)[0]
    confidence = float(np.max(probas))

    info = GITHUB_LABEL_MAP.get(prediction, GITHUB_LABEL_MAP[0])
    label = info["display"]
    category = info["category"]
    severity = info["severity"]
    pkt_size = int(body.features[1]) if body.features[1] > 0 else 64

    payload = {
        "timestamp":      int(time.time() * 1000),
        "sourceNode":     "ML-Injection",
        "sourceIp":       body.source_ip,
        "destIp":         body.dest_ip,
        "protocol":       body.protocol,
        "port":           body.port,
        "packetSize":     pkt_size,
        "classification": label,
        "category":       category,
        "severityScore":  int(severity),
        "confidence":     round(confidence, 3),
        "throughputMbps": round(pkt_size * 8 / 1e6, 4),
        "pps":            1,
        "source":         "feature_injection",
    }
    await manager.broadcast(payload)
    return {
        "status": "classified",
        "prediction": prediction,
        "classification": label,
        "confidence": round(confidence, 3),
        "category": category,
    }

#  ESP32 Custom Model API (Receives from live_guardian.py) 
class ESP32LiveFeatures(BaseModel):
    total_packets: float
    total_bytes: float
    packet_rate: float
    byte_rate: float
    prediction: int = -1 # Optional: If live_guardian does the prediction

@app.post("/api/esp32-traffic")
async def receive_esp32_traffic(features: ESP32LiveFeatures):
    # Update ESP32 device heartbeat
    esp32_device["last_seen"] = time.time()
    esp32_device["online"] = True
    esp32_device["packet_rate"] = features.packet_rate
    esp32_device["byte_rate"] = features.byte_rate

    pred = features.prediction
    conf = 1.0

    # If live_guardian didn't send a prediction, we do it here
    if pred == -1 and esp32_model is not None:
        f = [[features.total_packets, features.total_bytes, features.packet_rate, features.byte_rate]]
        pred = int(esp32_model.predict(f)[0])
        try:
            probas = esp32_model.predict_proba(f)[0]
            conf = float(np.max(probas))
        except:
            pass

    if pred == -1:
        pred = 0 # Default benign if model failed

    info = ESP32_LABEL_MAP.get(pred, ESP32_LABEL_MAP[0])
    label = info["display"]
    category = info["category"]
    severity = info["severity"]

    payload = {
        "timestamp":      int(time.time() * 1000),
        "sourceNode":     "ESP32-Guardian",
        "sourceIp":       "live",
        "destIp":         "local",
        "protocol":       "MIX",
        "port":           0,
        "packetSize":     int(features.total_bytes / max(features.total_packets, 1)),
        "classification": label,
        "category":       category,
        "severityScore":  int(severity),
        "confidence":     round(conf, 3),
        "throughputMbps": float(round((features.byte_rate * 8) / 1e6, 4)),
        "pps":            int(round(features.packet_rate)),
        "source":         "esp32_custom",
    }
    # Update device prediction status
    esp32_device["last_prediction"] = label
    esp32_device["last_severity"] = int(severity)

    await manager.broadcast(payload)
    return {"status": "received", "prediction": label, "severity": severity}

# ── ESP32 Device Status API ──────────────────────────────────────────────────
@app.get("/api/esp32/status")
async def get_esp32_status():
    """Returns the current ESP32 device status for dashboard polling."""
    # Auto-detect offline if no heartbeat in 10 seconds
    if esp32_device["last_seen"] > 0 and (time.time() - esp32_device["last_seen"]) > 10:
        esp32_device["online"] = False
    return {
        "online": esp32_device["online"],
        "last_seen": esp32_device["last_seen"],
        "packet_rate": esp32_device["packet_rate"],
        "byte_rate": esp32_device["byte_rate"],
        "last_prediction": esp32_device["last_prediction"],
        "last_severity": esp32_device["last_severity"],
        "camera_status": esp32_device["camera_status"],
        "target_ip": esp32_device["target_ip"],
    }

class CameraStatusUpdate(BaseModel):
    status: str  # STREAMING, FROZEN, DOWN
    target_ip: str = "192.168.166.167"

@app.post("/api/esp32/camera-status")
async def update_camera_status(body: CameraStatusUpdate):
    """Called by live_guardian.py to report ESP32-CAM health."""
    esp32_device["camera_status"] = body.status
    esp32_device["target_ip"] = body.target_ip
    return {"status": "updated", "camera_status": body.status}

#  Authentication API 
class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
async def login(req: LoginRequest):
    # Simple hardcoded auth for the prototype
    if req.username == "admin" and req.password == "admin":
        return {"access_token": "esp32-secure-token-2026", "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/api/verify-token")
async def verify_token(token: str = Query(None)):
    if token == "esp32-secure-token-2026":
        return {"valid": True}
    return {"valid": False}

#  TShark Interface List 
@app.get("/api/interfaces")
async def list_interfaces():
    try:
        result = subprocess.run(
            ["tshark", "-D"], capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
        )
        lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
        interfaces = []
        for line in lines:
            parts = line.split(' ', 1)
            if len(parts) == 2:
                num = parts[0].rstrip('.')
                name = parts[1].strip()
                interfaces.append({"id": num, "name": name})
        return {"interfaces": interfaces}
    except Exception as e:
        return {"interfaces": [], "error": str(e)}

#  Layer2 API (external script can POST features directly) 
class Layer2LiveFeatures(BaseModel):
    packet_rate:    float
    unique_dst_ips: int
    unique_src_ips: int
    mean_pkt_size:  float
    std_pkt_size:   float
    protocol_count: int

@app.post("/alert_layer2")
async def receive_layer2_live(features: Layer2LiveFeatures):
    f = [[
        features.packet_rate, features.unique_dst_ips, features.unique_src_ips,
        features.mean_pkt_size, features.std_pkt_size, features.protocol_count
    ]]
    pred, conf = 0, 1.0
    if layer2_model is not None:
        pred = int(layer2_model.predict(f)[0])
        probas = layer2_model.predict_proba(f)[0]
        conf = float(np.max(probas))

    if pred == 0:
        label, severity, category = "BENIGN", 0, "benign"
    else:
        if features.unique_dst_ips > 30:
            label, severity, category = "Scan-Host", 52, "recon"
        elif features.packet_rate > 200 and features.mean_pkt_size < 100:
            label, severity, category = "DoS-SYN", 88, "dos"
        elif features.packet_rate > 100 and features.unique_src_ips > 10:
            label, severity, category = "Mirai-UDP", 86, "ddos"
        else:
            label, severity, category = "Host Discovery", 55, "recon"

    payload = {
        "timestamp":      int(time.time() * 1000),
        "sourceNode":     "Live-WiFi",
        "sourceIp":       "live",
        "destIp":         "local",
        "protocol":       "MIX",
        "port":           0,
        "packetSize":     int(features.mean_pkt_size),
        "classification": label,
        "category":       category,
        "severityScore":  int(severity),
        "confidence":     round(conf, 3),
        "throughputMbps": float(round(features.packet_rate * features.mean_pkt_size * 8 / 1e6, 4)),
        "pps":            int(round(features.packet_rate)),
        "source":         "layer2",
    }
    await manager.broadcast(payload)
    return {"status": "received", "prediction": label}

#  File Analysis 
BOT_IOT_FEATURES = ['pkSeqID', 'seq', 'stddev', 'N_IN_Conn_P_SrcIP', 'min',
                    'state_number', 'mean', 'N_IN_Conn_P_DstIP', 'drate',
                    'srate', 'max', 'attack']

def _classify_csv(df: pd.DataFrame):
    if len(df) > 10000:
        df = df.head(10000)
    for f in BOT_IOT_FEATURES:
        if f not in df.columns:
            df[f] = 0
    df_feat = df[BOT_IOT_FEATURES].copy()
    preds   = bot_iot_model.predict(df_feat.values)
    probas  = bot_iot_model.predict_proba(df_feat.values)
    labels  = label_encoder.inverse_transform(preds)
    records, benign_cnt, attack_cnt = [], 0, 0
    for i, row in enumerate(df.itertuples(index=False)):
        raw = labels[i]
        info = resolve_label(raw)
        conf = float(np.max(probas[i]))
        src = str(getattr(row, 'saddr', '-'))
        dst = str(getattr(row, 'daddr', '-'))
        proto = str(getattr(row, 'proto', '-')).upper()
        port  = str(getattr(row, 'dport', '-'))
        size  = int(getattr(row, 'mean', 0))
        if info["category"] == "benign":
            benign_cnt += 1
        else:
            attack_cnt += 1
        records.append({
            "row": i + 1, "sourceIp": src, "destIp": dst, "protocol": proto,
            "port": port, "packetSize": size, "classification": info["display"],
            "category": info["category"], "confidence": round(conf, 3),
        })
    return records, benign_cnt, attack_cnt

@app.post("/api/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    fname = file.filename.lower()
    is_csv = fname.endswith(".csv")
    if not is_csv:
        raise HTTPException(400, "Upload a .csv file")
    try:
        raw = await file.read()
        df = pd.read_csv(io.BytesIO(raw))
        if bot_iot_model is None:
            raise HTTPException(500, "XGBoost model not loaded")
        records, benign_cnt, attack_cnt = _classify_csv(df)
        return {
            "status": "success", "filename": file.filename,
            "totalRecords": len(records), "fileType": "CSV",
            "benignCount": benign_cnt, "attackCount": attack_cnt,
            "records": records,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, detail=str(e))

#  Static File Serving (built frontend) 
FRONTEND_DIST = Path(__file__).parent.parent / "ids-frontend" / "dist"

if FRONTEND_DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        file_path = FRONTEND_DIST / full_path
        if full_path and file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(FRONTEND_DIST / "index.html"))

    print(f"[IDS] Frontend: {FRONTEND_DIST}")
else:
    print("[IDS] No frontend build. Run 'npm run build' in ids-frontend/")
