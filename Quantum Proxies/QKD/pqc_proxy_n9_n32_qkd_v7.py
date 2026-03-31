#!/usr/bin/env python3
"""
Unified QKD-KMS keyed TLS proxy (UDP + 2x TCP) with:
- Shared SAE key pool (enc_keys)
- KeySync + dec_keys buffering on KME
- Alternating TLS ports per service (overlay) to avoid packet loss on rekey
- OPTIMIZED: TCP_NODELAY enabled on data planes to prevent Nagle/Delayed-ACK latency spikes.
- FIXED: UDP pipe short-read fragmentation, UDP race conditions, and SAE key multipliers.
- MEASUREMENT EXTENDED: Tracks key pops, connections, and Mode 2 byte states.
"""

import argparse
import base64
import csv
import json
import math
import os
import queue
import select
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Deque, Dict, List, Optional, Tuple
from collections import deque

import requests

# =============================================================================
# ===== Convenience configuration (keep everything here, no external exports) ===
# =============================================================================

# ----- Execution / temp dir -----
TMP_DIR = "./tmp_qkd"

# ----- Results / measurement output -----
RESULTS_DIR = "results"
MEASURE_ASSUME_KME_BUFFERED = False  # Set to False to prevent double-counting
MEASURE_MULTIPLIER = 1             # 1 key fetched = 256 bits logged

# ----- KMS endpoints -----
KMS_ENC_IP = "10.250.0.2"  # SAE-side KMS
KMS_DEC_IP = "10.250.1.2"  # KME-side KMS
KMS_PORT = 80

# UUIDs
KMS_ENC_UUID = "aaac7de9-5826-11ef-8057-9b39f247aaa"
KMS_DEC_UUID = "bbbc7de9-5826-11ef-8057-9b39f247bbb"

# ----- enc_keys query parameters -----
KMS_ENC_NUMBER = 3
KMS_KEY_SIZE = 256  # bits (as agreed)

# ----- Shared SAE key pool behavior -----
SAE_POOL_TARGET = 10         # cap; only inserted keys are counted
SAE_POOL_LOW_WATER = 7
SAE_KMS_POLL_SEC = 2.0

# ----- Rotation (consumption) loops -----
# Time-based rotation intervals
UDP_KEY_REFRESH_SEC = 30
TCP1_KEY_REFRESH_SEC = 30
TCP2_KEY_REFRESH_SEC = 30

# Payload-based rotation thresholds (bytes)
UDP_SWITCH_BYTES = 10 * 1024 * 1024        # 10 MiB default
TCP1_SWITCH_BYTES = 2 * 1024 * 1024  # 2 MiB default
TCP2_SWITCH_BYTES = 2 * 1024 * 1024  # 2 MiB default

# ----- KeySync control plane (SAE -> KME) -----
KEYSYNC_PORT = 9090
KEYSYNC_HOST = None  # if None, SAE uses KME_HOST below

# ----- SAE <-> KME data-plane (TLS) addresses -----
KME_HOST = "10.100.1.207"

# TCP1 TLS ports
TCP1_TLS_PORT_A = 8243
TCP1_TLS_PORT_B = 8244

# TCP2 TLS ports
TCP2_TLS_PORT_A = 8343
TCP2_TLS_PORT_B = 8344

# UDP TLS ports
UDP_TLS_PORT_A = 8443
UDP_TLS_PORT_B = 8444

# ----- UDP forwarding plane -----
SAE_UDP_LISTEN_HOST = "0.0.0.0"
SAE_UDP_LISTEN_PORT = 2152

KME_UDP_EGRESS_HOST = "10.100.2.205"
KME_UDP_EGRESS_PORT = 2152

# ----- TCP forwarding plane -----
# TCP1
SAE_TCP1_LISTEN_HOST = "0.0.0.0"
SAE_TCP1_LISTEN_PORT = 6666

# TCP2
SAE_TCP2_LISTEN_HOST = "0.0.0.0"
SAE_TCP2_LISTEN_PORT = 7777

# ----- TCP backends (KME side) -----
# TCP1 backend
KME_TCP1_BACKEND_HOST = "10.10.2.251"
KME_TCP1_BACKEND_PORT = 7777

# TCP2 backend
KME_TCP2_BACKEND_HOST = "10.10.2.252"
KME_TCP2_BACKEND_PORT = 7777

# ----- Rekey overlay behavior -----
RETIRE_GRACE_SEC_UDP = 2.0
RETIRE_GRACE_SEC_TCP = 10.0

# ----- OpenSSL behavior -----
OPENSSL_BIN = "openssl"
OPENSSL_FORCE_TLS13 = True
OPENSSL_TLS13_CIPHERSUITES = ""  # optionally set TLS_AES_256_GCM_SHA384 etc.

# Cert fallback (off by default)
ENABLE_CERT_FALLBACK = False
CERT_FILE = "./server.crt"
KEY_FILE = "./server.key"

# ----- Robustness / timeouts -----
KMS_HTTP_TIMEOUT_SEC = 3.0
TCP_BACKEND_CONNECT_TIMEOUT_SEC = 3.0

# TCP TLS connect retry (SAE side)
SAE_TCP_TLS_CONNECT_RETRY_SEC = 3.0
SAE_TCP_TLS_CONNECT_RETRY_STEP = 0.2

# ----- Framing for UDP-over-TLS -----
UDP_FRAME_LEN_BYTES = 2
UDP_MAX_PAYLOAD = 2048


# =============================================================================
# ============================ Utility helpers ================================
# =============================================================================

def _ensure_tmp_dir() -> None:
    os.makedirs(TMP_DIR, exist_ok=True)

def _b64_to_bytes(b64_s: str) -> bytes:
    return base64.b64decode((b64_s or "").strip())

def _bytes_to_hex(b: bytes) -> str:
    return b.hex()

def _log(prefix: str, msg: str) -> None:
    print(f"[{prefix}] {msg}", flush=True)

def _kill_proc(p: subprocess.Popen, name: str) -> None:
    try:
        p.terminate()
        try:
            p.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            p.kill()
    except Exception as e:
        _log("PROC", f"{name} kill exception: {repr(e)}")

def _build_openssl_tls13_args() -> List[str]:
    args: List[str] = []
    if OPENSSL_FORCE_TLS13:
        args += ["-tls1_3"]
    if OPENSSL_TLS13_CIPHERSUITES:
        args += ["-ciphersuites", OPENSSL_TLS13_CIPHERSUITES]
    return args

def _openssl_s_server_psk(port: int, psk_hex: str, psk_identity: str) -> subprocess.Popen:
    cmd = [
        OPENSSL_BIN, "s_server",
        "-accept", str(port),
        "-quiet",
        "-nocert",
        "-psk", psk_hex,
        "-psk_identity", psk_identity,
        "-naccept", "1",
    ] + _build_openssl_tls13_args()

    return subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )

def _openssl_s_server_cert(port: int) -> subprocess.Popen:
    cmd = [
        OPENSSL_BIN, "s_server",
        "-accept", str(port),
        "-quiet",
        "-cert", CERT_FILE,
        "-key", KEY_FILE,
        "-naccept", "1",
    ] + _build_openssl_tls13_args()

    return subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )

def _openssl_s_client_psk(host: str, port: int, psk_hex: str, psk_identity: str) -> subprocess.Popen:
    cmd = [
        OPENSSL_BIN, "s_client",
        "-connect", f"{host}:{port}",
        "-quiet",
        "-psk", psk_hex,
        "-psk_identity", psk_identity,
    ] + _build_openssl_tls13_args()

    return subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )

def _drain_stderr(p: subprocess.Popen, prefix: str, max_bytes: int = 4096) -> str:
    try:
        if p.stderr is None:
            return ""
        r = p.stderr.read1(max_bytes) if hasattr(p.stderr, "read1") else p.stderr.read(max_bytes)
        if not r:
            return ""
        s = r.decode(errors="replace")
        if s.strip():
            _log(prefix, s.strip())
        return s
    except Exception:
        return ""

def _parse_switch_tag(tag: str) -> Tuple[int, int, int]:
    if len(tag) != 3 or any(c not in "123" for c in tag):
        raise ValueError("switch tag must be exactly 3 digits, each in {1,2,3}")
    t1 = int(tag[0])
    t2 = int(tag[1])
    u = int(tag[2])
    if u == 3:
        u = 1
    return t1, t2, u


# =============================================================================
# ============================ Measurement (SAE) ===============================
# =============================================================================

class SaeMeasure:
    """
    Records per-second telemetry:
    - newly buffered bits
    - keys consumed per service
    - new TCP connections accepted
    - payload bytes processed by current key (Mode 2)
    """
    def __init__(self, out_csv_path: str, key_size_bits: int, multiplier: int = 1) -> None:
        self.out_csv_path = out_csv_path
        self.key_size_bits = int(key_size_bits)
        self.multiplier = int(multiplier)
        self.start_ts = time.time()

        self._lock = threading.Lock()
        self._stats_by_sec: Dict[int, Dict[str, int]] = {}

    def _event_sec(self) -> int:
        elapsed = time.time() - self.start_ts
        return max(1, int(math.ceil(elapsed)))

    def _get_sec(self, sec: int) -> Dict[str, int]:
        if sec not in self._stats_by_sec:
            self._stats_by_sec[sec] = {
                "buf_bits": 0,
                "pop_udp": 0, "pop_tcp1": 0, "pop_tcp2": 0,
                "conn_tcp1": 0, "conn_tcp2": 0
            }
        return self._stats_by_sec[sec]

    def record_keys_inserted(self, inserted_keys: int) -> None:
        if inserted_keys <= 0:
            return
        bits = inserted_keys * self.key_size_bits * self.multiplier
        sec = self._event_sec()
        with self._lock:
            self._get_sec(sec)["buf_bits"] += bits

    def record_key_pop(self, svc_name: str) -> None:
        sec = self._event_sec()
        with self._lock:
            self._get_sec(sec)[f"pop_{svc_name}"] += 1

    def record_conn(self, svc_name: str) -> None:
        sec = self._event_sec()
        with self._lock:
            if f"conn_{svc_name}" in self._get_sec(sec):
                self._get_sec(sec)[f"conn_{svc_name}"] += 1

    def pop_stats_for_sec(self, sec: int) -> Dict[str, int]:
        with self._lock:
            return self._stats_by_sec.pop(sec, {
                "buf_bits": 0,
                "pop_udp": 0, "pop_tcp1": 0, "pop_tcp2": 0,
                "conn_tcp1": 0, "conn_tcp2": 0
            })

    def run_writer(self, state) -> None:
        os.makedirs(os.path.dirname(self.out_csv_path) or ".", exist_ok=True)
        with open(self.out_csv_path, "w", newline="") as f:
            w = csv.writer(f)
            headers = [
                "time_sec", "newly_buffered_bits", 
                "keys_popped_udp", "keys_popped_tcp1", "keys_popped_tcp2",
                "new_conns_tcp1", "new_conns_tcp2",
                "mode2_bytes_on_key_udp", "mode2_bytes_on_key_tcp1", "mode2_bytes_on_key_tcp2"
            ]
            w.writerow(headers)
            w.writerow([0] * len(headers))
            f.flush()

            last_written = 0
            while not state.stop.is_set():
                elapsed = time.time() - self.start_ts
                completed = int(elapsed) 

                for sec in range(last_written + 1, completed + 1):
                    stats = self.pop_stats_for_sec(sec)
                    
                    # Snapshot the live bytes_since_rotate directly from the services
                    b_udp = state.udp.bytes_since_rotate if state.udp_mode == 2 else 0
                    b_tcp1 = state.tcp1.bytes_since_rotate if state.tcp1_mode == 2 else 0
                    b_tcp2 = state.tcp2.bytes_since_rotate if state.tcp2_mode == 2 else 0

                    w.writerow([
                        sec, stats["buf_bits"],
                        stats["pop_udp"], stats["pop_tcp1"], stats["pop_tcp2"],
                        stats["conn_tcp1"], stats["conn_tcp2"],
                        b_udp, b_tcp1, b_tcp2
                    ])
                    f.flush()
                    last_written = sec
                state.stop.wait(0.2)

            # Final flush on stop
            elapsed = time.time() - self.start_ts
            final_sec = max(0, int(math.ceil(elapsed)))
            for sec in range(last_written + 1, final_sec + 1):
                stats = self.pop_stats_for_sec(sec)
                b_udp = state.udp.bytes_since_rotate if state.udp_mode == 2 else 0
                b_tcp1 = state.tcp1.bytes_since_rotate if state.tcp1_mode == 2 else 0
                b_tcp2 = state.tcp2.bytes_since_rotate if state.tcp2_mode == 2 else 0
                w.writerow([
                    sec, stats["buf_bits"],
                    stats["pop_udp"], stats["pop_tcp1"], stats["pop_tcp2"],
                    stats["conn_tcp1"], stats["conn_tcp2"],
                    b_udp, b_tcp1, b_tcp2
                ])
                f.flush()


# =============================================================================
# ============================ KMS client =====================================
# =============================================================================

def kms_enc_url() -> str:
    return f"http://{KMS_ENC_IP}:{KMS_PORT}/api/v1/keys/{KMS_ENC_UUID}/enc_keys/number/{KMS_ENC_NUMBER}/size/{KMS_KEY_SIZE}"

def kms_dec_url() -> str:
    return f"http://{KMS_DEC_IP}:{KMS_PORT}/api/v1/keys/{KMS_DEC_UUID}/dec_keys"

def _parse_json_bytes(raw: bytes) -> dict:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty response body")
    if len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B:
        import gzip
        raw = gzip.decompress(raw).strip()
    return json.loads(raw.decode("utf-8", errors="strict"))

def kms_fetch_enc_keys() -> List[Tuple[str, str]]:
    url = kms_enc_url()
    headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
    r = requests.get(url, headers=headers, timeout=KMS_HTTP_TIMEOUT_SEC, stream=True)
    try: r.raw.decode_content = False
    except: pass
    r.raise_for_status()
    obj = _parse_json_bytes(r.raw.read())
    out: List[Tuple[str, str]] = []
    for k in obj.get("keys", []):
        kid = k.get("key_ID", "")
        kb64 = k.get("key", "")
        if kid and kb64: out.append((kid, _bytes_to_hex(_b64_to_bytes(kb64))))
    return out

def kms_fetch_dec_keys(key_ids: List[str]) -> Dict[str, str]:
    url = kms_dec_url()
    headers = {"Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "identity"}
    body = {"key_IDs": [{"key_ID": kid} for kid in key_ids]}
    r = requests.post(url, headers=headers, json=body, timeout=KMS_HTTP_TIMEOUT_SEC, stream=True)
    try: r.raw.decode_content = False
    except: pass
    r.raise_for_status()
    obj = _parse_json_bytes(r.raw.read())
    out: Dict[str, str] = {}
    for k in obj.get("keys", []):
        kid = k.get("key_ID", "")
        kb64 = k.get("key", "")
        if kid and kb64: out[kid] = _bytes_to_hex(_b64_to_bytes(kb64))
    return out


# =============================================================================
# ===================== Shared SAE key pool + consumers =======================
# =============================================================================

class SaeKeyPool:
    def __init__(self) -> None:
        self._fifo: Deque[Tuple[str, str]] = deque()
        self._lock = threading.Lock()

    def size(self) -> int:
        with self._lock: return len(self._fifo)

    def push_many_capped(self, keys: List[Tuple[str, str]], cap: Optional[int]) -> List[Tuple[str, str]]:
        inserted: List[Tuple[str, str]] = []
        with self._lock:
            for k in keys:
                if cap is not None and len(self._fifo) >= cap: break
                self._fifo.append(k)
                inserted.append(k)
        return inserted

    def push_front(self, k: Tuple[str, str]) -> None:
        with self._lock: self._fifo.appendleft(k)

    def pop_one(self) -> Optional[Tuple[str, str]]:
        with self._lock:
            if not self._fifo: return None
            return self._fifo.popleft()


# =============================================================================
# ============================ KeySync protocol ===============================
# =============================================================================

def keysync_post(payload: dict) -> bool:
    host = KEYSYNC_HOST or KME_HOST
    url = f"http://{host}:{KEYSYNC_PORT}/keys"
    try:
        r = requests.post(url, json=payload, timeout=KMS_HTTP_TIMEOUT_SEC)
        return r.status_code == 200
    except Exception as e:
        _log("SAE-KMS", f"KeySync POST exception: {repr(e)}")
        return False


# =============================================================================
# ============================ UDP framing helpers ============================
# =============================================================================

def udp_frame_pack(payload: bytes) -> bytes:
    if len(payload) > 0xFFFF:
        payload = payload[:0xFFFF]
    return len(payload).to_bytes(UDP_FRAME_LEN_BYTES, "big") + payload

def udp_frame_read_from_pipe(pipe, timeout: float = 0.1) -> Optional[bytes]:
    rlist, _, _ = select.select([pipe], [], [], timeout)
    if not rlist:
        return None
    
    def _read_exact(n: int) -> Optional[bytes]:
        buf = bytearray()
        while len(buf) < n:
            chunk = pipe.read(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    hdr = _read_exact(UDP_FRAME_LEN_BYTES)
    if not hdr:
        return None
        
    ln = int.from_bytes(hdr, "big")
    if ln <= 0 or ln > (UDP_MAX_PAYLOAD * 8):
        return None
        
    data = _read_exact(ln)
    return data


# =============================================================================
# ============================== SAE side =====================================
# =============================================================================

class SaeServiceState:
    def __init__(self, name: str, port_a: int, port_b: int) -> None:
        self.name = name
        self.port_a = port_a
        self.port_b = port_b
        self.active_port = port_a

        self.key_id: Optional[str] = None
        self.psk_hex: Optional[str] = None

        self.bytes_since_rotate = 0
        self.rotate_req = threading.Event()

class SaeState:
    def __init__(self, pool: SaeKeyPool, tcp1_mode: int, tcp2_mode: int, udp_mode: int, meas: Optional[SaeMeasure]) -> None:
        self.pool = pool
        self.tcp1_mode = tcp1_mode
        self.tcp2_mode = tcp2_mode
        self.udp_mode = udp_mode
        self.meas = meas

        self.udp = SaeServiceState("udp", UDP_TLS_PORT_A, UDP_TLS_PORT_B)
        self.tcp1 = SaeServiceState("tcp1", TCP1_TLS_PORT_A, TCP1_TLS_PORT_B)
        self.tcp2 = SaeServiceState("tcp2", TCP2_TLS_PORT_A, TCP2_TLS_PORT_B)

        self._udp_client_lock = threading.Lock()
        self._udp_client: Optional[subprocess.Popen] = None

        self.stop = threading.Event()

def sae_pool_maintainer(state: SaeState) -> None:
    while not state.stop.is_set():
        try:
            if state.pool.size() < SAE_POOL_LOW_WATER:
                keys = kms_fetch_enc_keys()
                if keys:
                    inserted = state.pool.push_many_capped(keys, SAE_POOL_TARGET)
                    if inserted:
                        if state.meas is not None:
                            state.meas.record_keys_inserted(len(inserted))
                        payload = {"op": "prefetch", "key_IDs": [{"key_ID": kid} for (kid, _) in inserted]}
                        keysync_post(payload)
        except Exception: pass
        state.stop.wait(SAE_KMS_POLL_SEC)

def _sae_commit_initial_service(service: str, kid: str, port_a: int, port_b: int) -> bool:
    if not keysync_post({"op": "prepare", "service": service, "key_ID": kid, "port": port_a}): return False
    return keysync_post({"op": "commit", "service": service, "key_ID": kid, "new_port": port_a, "old_port": port_b, "grace": 0.0})

def _sae_rotate_service(state: SaeState, svc: SaeServiceState, grace: float) -> bool:
    km = state.pool.pop_one()
    if not km: return False

    new_kid, new_psk = km
    old_port = svc.active_port
    new_port = svc.port_b if old_port == svc.port_a else svc.port_a

    if not keysync_post({"op": "prepare", "service": svc.name, "key_ID": new_kid, "port": new_port}):
        state.pool.push_front(km)
        return False

    if not keysync_post({"op": "commit", "service": svc.name, "key_ID": new_kid, "new_port": new_port, "old_port": old_port, "grace": grace}):
        state.pool.push_front(km)
        return False

    svc.key_id, svc.psk_hex = new_kid, new_psk
    svc.active_port = new_port
    svc.bytes_since_rotate = 0
    
    # Record that the key was officially popped and used
    if state.meas is not None:
        state.meas.record_key_pop(svc.name)
        
    _log("SAE-KMS", f"{svc.name.upper()} Switched key_ID={new_kid} -> port={new_port}; sae_pool={state.pool.size()} (low={SAE_POOL_LOW_WATER})")
    return True

# ---------------- UDP data plane (persistent TLS tunnel) ----------------

def sae_udp_restart_client(state: SaeState) -> None:
    with state._udp_client_lock:
        if state._udp_client is not None:
            _kill_proc(state._udp_client, "sae_udp_s_client")
            state._udp_client = None

        if not state.udp.key_id or not state.udp.psk_hex: return

        port = state.udp.active_port
        psk = state.udp.psk_hex
        kid = state.udp.key_id

        _log("SAE-TLS", f"UDP persistent s_client connecting to {KME_HOST}:{port} key_ID={kid}")
        
        deadline = time.time() + SAE_TCP_TLS_CONNECT_RETRY_SEC
        p = None
        while time.time() < deadline and not state.stop.is_set():
            p = _openssl_s_client_psk(KME_HOST, port, psk, kid)
            probe_deadline = time.time() + 0.005
            while p.poll() is None and time.time() < probe_deadline: time.sleep(0.001)
            if p.poll() is None: break
            _drain_stderr(p, "SAE-OPENSSL-UDP")
            _kill_proc(p, "sae_udp_s_client")
            p = None
            time.sleep(SAE_TCP_TLS_CONNECT_RETRY_STEP)

        state._udp_client = p

def sae_udp_send_frame(state: SaeState, payload: bytes) -> bool:
    with state._udp_client_lock:
        p = state._udp_client
        if p is None or p.stdin is None: return False
        try:
            p.stdin.write(udp_frame_pack(payload))
            p.stdin.flush()
            return True
        except Exception: return False

def sae_udp_proxy_loop(state: SaeState) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SAE_UDP_LISTEN_HOST, SAE_UDP_LISTEN_PORT))

    while not state.stop.is_set():
        try:
            rlist, _, _ = select.select([sock], [], [], 0.5)
            if not rlist: continue
            data, _ = sock.recvfrom(UDP_MAX_PAYLOAD)
            if not state.udp.key_id: continue

            if state.udp_mode == 2:
                state.udp.bytes_since_rotate += len(data)
                if state.udp.bytes_since_rotate >= UDP_SWITCH_BYTES:
                    state.udp.rotate_req.set()

            if not sae_udp_send_frame(state, data):
                sae_udp_restart_client(state)
                sae_udp_send_frame(state, data)
        except Exception: continue

def sae_udp_rotator(state: SaeState) -> None:
    while not state.stop.is_set() and state.udp.key_id is None:
        km = state.pool.pop_one()
        if not km:
            state.stop.wait(0.1)
            continue
        kid, psk = km
        state.udp.key_id, state.udp.psk_hex = kid, psk
        state.udp.active_port = state.udp.port_a
        state.udp.bytes_since_rotate = 0
        
        # Record initial key pop
        if state.meas is not None:
            state.meas.record_key_pop("udp")

        if not _sae_commit_initial_service("udp", kid, state.udp.port_a, state.udp.port_b):
            state.pool.push_front((kid, psk))
            state.udp.key_id = None
            state.udp.psk_hex = None
            state.stop.wait(1.0)
            continue

        sae_udp_restart_client(state)
        break

    while not state.stop.is_set():
        if state.udp_mode == 1:
            state.stop.wait(UDP_KEY_REFRESH_SEC)
            if state.stop.is_set(): break
            if _sae_rotate_service(state, state.udp, RETIRE_GRACE_SEC_UDP):
                sae_udp_restart_client(state)
        else:
            next_deadline = time.time() + UDP_KEY_REFRESH_SEC
            while not state.stop.is_set():
                time_left = next_deadline - time.time()
                if time_left <= 0:
                    state.udp.rotate_req.clear()
                    if _sae_rotate_service(state, state.udp, RETIRE_GRACE_SEC_UDP):
                        sae_udp_restart_client(state)
                    next_deadline = time.time() + UDP_KEY_REFRESH_SEC
                    continue

                state.udp.rotate_req.wait(timeout=min(0.5, time_left))
                if state.stop.is_set(): break
                if not state.udp.rotate_req.is_set(): continue
                state.udp.rotate_req.clear()
                if _sae_rotate_service(state, state.udp, RETIRE_GRACE_SEC_UDP):
                    sae_udp_restart_client(state)
                next_deadline = time.time() + UDP_KEY_REFRESH_SEC


# ---------------- TCP data plane (per-client TLS tunnel) ----------------

def _sae_tcp_listener_loop(
    state: SaeState,
    svc: SaeServiceState,
    listen_host: str,
    listen_port: int,
    tls_port_a: int,
    tls_port_b: int,
    mode: int,
    switch_bytes: int,
    backend_label: str,
) -> None:
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((listen_host, listen_port))
    ls.listen(50)

    while not state.stop.is_set():
        try:
            rlist, _, _ = select.select([ls], [], [], 0.5)
            if not rlist: continue
            cs, caddr = ls.accept()
            cs.setblocking(False)
            cs.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            # Record incoming connection detected
            if state.meas is not None:
                state.meas.record_conn(svc.name)

            if mode == 3:
                if not _sae_rotate_service(state, svc, RETIRE_GRACE_SEC_TCP):
                    cs.close()
                    continue

            if not svc.key_id or not svc.psk_hex:
                cs.close()
                continue

            port = svc.active_port
            kid = svc.key_id
            psk = svc.psk_hex

            deadline = time.time() + SAE_TCP_TLS_CONNECT_RETRY_SEC
            p: Optional[subprocess.Popen] = None
            while time.time() < deadline and not state.stop.is_set():
                p = _openssl_s_client_psk(KME_HOST, port, psk, kid)
                probe_deadline = time.time() + 0.005
                while p.poll() is None and time.time() < probe_deadline: time.sleep(0.001)
                if p.poll() is None: break
                _drain_stderr(p, "SAE-OPENSSL")
                _kill_proc(p, f"{svc.name}_s_client")
                p = None
                time.sleep(SAE_TCP_TLS_CONNECT_RETRY_STEP)

            if p is None or p.stdin is None or p.stdout is None:
                cs.close()
                continue

            alive = True

            while alive and not state.stop.is_set():
                if p.poll() is not None: break

                rset = [cs, p.stdout]
                rlist2, _, _ = select.select(rset, [], [], 0.5)

                for rsrc in rlist2:
                    if rsrc is cs:
                        try:
                            data = cs.recv(4096)
                            if not data: alive = False; break
                            
                            # ==== LIVE TCP BYTE TRACKING ====
                            if mode == 2 and svc.key_id == kid:
                                svc.bytes_since_rotate += len(data)
                                if svc.bytes_since_rotate >= switch_bytes:
                                    svc.bytes_since_rotate = 0
                                    _sae_rotate_service(state, svc, RETIRE_GRACE_SEC_TCP)
                            # ================================

                            p.stdin.write(data)
                            p.stdin.flush()
                        except BlockingIOError: pass
                        except Exception: alive = False; break
                    else:
                        try:
                            data = p.stdout.read1(4096) if hasattr(p.stdout, "read1") else p.stdout.read(4096)
                            if not data: alive = False; break
                            cs.sendall(data)
                        except BlockingIOError: pass
                        except Exception: alive = False; break

            cs.close()
            _kill_proc(p, f"{svc.name}_s_client")

        except Exception: continue

def _sae_tcp_time_rotator(state: SaeState, svc: SaeServiceState, refresh_sec: float, mode: int) -> None:
    if mode not in (1, 2): return

    while not state.stop.is_set() and svc.key_id is None:
        km = state.pool.pop_one()
        if not km:
            state.stop.wait(1.0)
            continue
        kid, psk = km
        svc.key_id, svc.psk_hex = kid, psk
        svc.active_port = svc.port_a
        svc.bytes_since_rotate = 0
        
        # Record initial key pop
        if state.meas is not None:
            state.meas.record_key_pop(svc.name)

        if not _sae_commit_initial_service(svc.name, kid, svc.port_a, svc.port_b):
            state.pool.push_front((kid, psk))
            svc.key_id = None
            svc.psk_hex = None
            state.stop.wait(1.0)
            continue
        break

    while not state.stop.is_set():
        state.stop.wait(refresh_sec)
        if state.stop.is_set(): break
        _sae_rotate_service(state, svc, RETIRE_GRACE_SEC_TCP)

def run_sae(tag: str, out_csv: str) -> None:
    _ensure_tmp_dir()
    tcp1_mode, tcp2_mode, udp_mode = _parse_switch_tag(tag)
    pool = SaeKeyPool()

    multiplier = MEASURE_MULTIPLIER
    meas = SaeMeasure(out_csv, key_size_bits=KMS_KEY_SIZE, multiplier=multiplier)
    st = SaeState(pool, tcp1_mode, tcp2_mode, udp_mode, meas)

    # Note the change here: passing 'st' into the run_writer thread
    threads = [
        threading.Thread(target=meas.run_writer, args=(st,), daemon=True),
        threading.Thread(target=sae_pool_maintainer, args=(st,), daemon=True),
        threading.Thread(target=sae_udp_rotator, args=(st,), daemon=True),
        threading.Thread(target=sae_udp_proxy_loop, args=(st,), daemon=True),
        threading.Thread(target=_sae_tcp_time_rotator, args=(st, st.tcp1, TCP1_KEY_REFRESH_SEC, tcp1_mode), daemon=True),
        threading.Thread(
            target=_sae_tcp_listener_loop,
            args=(st, st.tcp1, SAE_TCP1_LISTEN_HOST, SAE_TCP1_LISTEN_PORT, TCP1_TLS_PORT_A, TCP1_TLS_PORT_B, tcp1_mode, TCP1_SWITCH_BYTES, "backend:tcp1"),
            daemon=True,
        ),
        threading.Thread(target=_sae_tcp_time_rotator, args=(st, st.tcp2, TCP2_KEY_REFRESH_SEC, tcp2_mode), daemon=True),
        threading.Thread(
            target=_sae_tcp_listener_loop,
            args=(st, st.tcp2, SAE_TCP2_LISTEN_HOST, SAE_TCP2_LISTEN_PORT, TCP2_TLS_PORT_A, TCP2_TLS_PORT_B, tcp2_mode, TCP2_SWITCH_BYTES, "backend:tcp2"),
            daemon=True,
        ),
    ]
    for t in threads: t.start()

    _log("MAIN", f"SAE running (UDP + TCP1 + TCP2). switch_tag={tag}")
    
    try:
        while True: time.sleep(1.0)
    except KeyboardInterrupt: pass
    finally:
        st.stop.set()
        with st._udp_client_lock:
            if st._udp_client is not None:
                _kill_proc(st._udp_client, "sae_udp_s_client")
        _log("MAIN", "SAE stopped.")


# =============================================================================
# ============================== KME side =====================================
# =============================================================================

class KmeKeyStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: Dict[str, str] = {}
        self._fifo: Deque[str] = deque()

    def add_many(self, kv: Dict[str, str]) -> int:
        added = 0
        with self._lock:
            for kid, psk in kv.items():
                if kid in self._by_id:
                    continue
                self._by_id[kid] = psk
                self._fifo.append(kid)
                added += 1
        return added

    def has(self, kid: str) -> bool:
        with self._lock:
            return kid in self._by_id

    def get(self, kid: str) -> Optional[str]:
        with self._lock:
            return self._by_id.get(kid)

    def size(self) -> int:
        with self._lock:
            return len(self._fifo)

class KmeServiceCtx:
    def __init__(self, name: str, port_a: int, port_b: int) -> None:
        self.name = name
        self.port_a = port_a
        self.port_b = port_b

        self.active_port = port_a
        self.active_key_id: Optional[str] = None

        self.retire_deadline: Optional[float] = None
        self.retire_port: Optional[int] = None
        self.retire_key_id: Optional[str] = None

        self.lock = threading.Lock()

class KmeState:
    def __init__(self) -> None:
        self.keys = KmeKeyStore()
        self.stop = threading.Event()
        self.udp = KmeServiceCtx("udp", UDP_TLS_PORT_A, UDP_TLS_PORT_B)
        self.tcp1 = KmeServiceCtx("tcp1", TCP1_TLS_PORT_A, TCP1_TLS_PORT_B)
        self.tcp2 = KmeServiceCtx("tcp2", TCP2_TLS_PORT_A, TCP2_TLS_PORT_B)
        self.prefetch_q: "queue.Queue[List[str]]" = queue.Queue()

def kme_prefetch_worker(st: KmeState) -> None:
    while not st.stop.is_set():
        try:
            kids = st.prefetch_q.get(timeout=0.5)
        except queue.Empty:
            continue
        try:
            kv = kms_fetch_dec_keys(kids)
            st.keys.add_many(kv)
        except Exception: pass

def _kme_ensure_dec_key(st: KmeState, kid: str) -> bool:
    if st.keys.has(kid): return True
    try:
        kv = kms_fetch_dec_keys([kid])
        st.keys.add_many(kv)
        return st.keys.has(kid)
    except Exception: return False

def kme_udp_tls_listener(st: KmeState, ctx: KmeServiceCtx) -> None:
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while not st.stop.is_set():
        with ctx.lock:
            if ctx.retire_deadline and time.time() >= ctx.retire_deadline:
                ctx.retire_deadline = None
                ctx.retire_port = None
                ctx.retire_key_id = None
            port = ctx.active_port
            kid = ctx.active_key_id

        if kid and st.keys.has(kid):
            psk = st.keys.get(kid)
            if not psk:
                time.sleep(0.1)
                continue
            proc = _openssl_s_server_psk(port, psk, kid)
        else:
            if ENABLE_CERT_FALLBACK:
                proc = _openssl_s_server_cert(port)
            else:
                time.sleep(0.1)
                continue

        try:
            if proc.stdout is None:
                _kill_proc(proc, "kme_udp_s_server")
                continue

            while not st.stop.is_set():
                if proc.poll() is not None:
                    break
                payload = udp_frame_read_from_pipe(proc.stdout, timeout=0.5)
                if payload is None:
                    continue
                us.sendto(payload, (KME_UDP_EGRESS_HOST, KME_UDP_EGRESS_PORT))
        finally:
            _kill_proc(proc, "kme_udp_s_server")

def _kme_ctx_tcp_port_kid(ctx: KmeServiceCtx, fixed_port: int, label: str) -> Optional[str]:
    now = time.time()
    with ctx.lock:
        if ctx.retire_deadline and now >= ctx.retire_deadline:
            ctx.retire_deadline = None
            ctx.retire_port = None
            ctx.retire_key_id = None

        if fixed_port == ctx.active_port:
            return ctx.active_key_id
        if ctx.retire_deadline and ctx.retire_port == fixed_port and now < ctx.retire_deadline:
            return ctx.retire_key_id
        return None

def kme_tcp_tls_port_worker(st: KmeState, ctx: KmeServiceCtx, fixed_port: int, backend_host: str, backend_port: int, label: str) -> None:
    listener_tag = f"{label}:{fixed_port}"
    while not st.stop.is_set():
        kid = _kme_ctx_tcp_port_kid(ctx, fixed_port, label)

        if kid and st.keys.has(kid):
            psk = st.keys.get(kid)
            if not psk:
                time.sleep(0.05)
                continue
            proc = _openssl_s_server_psk(fixed_port, psk, kid)
        else:
            if ENABLE_CERT_FALLBACK and kid is not None:
                proc = _openssl_s_server_cert(fixed_port)
            else:
                time.sleep(0.05)
                continue

        backend = None
        try:
            if proc.stdout is None or proc.stdin is None:
                _kill_proc(proc, f"kme_{label}_s_server")
                continue

            backend_connected = False

            while not st.stop.is_set():
                current_kid = _kme_ctx_tcp_port_kid(ctx, fixed_port, label)
                if current_kid != kid:
                    raise RuntimeError("Port role/key changed")

                if proc.poll() is not None: break

                rset = [proc.stdout]
                if backend is not None:
                    rset.append(backend)

                rlist, _, _ = select.select(rset, [], [], 0.5)
                if not rlist: continue

                for rsrc in rlist:
                    if rsrc is proc.stdout:
                        data = proc.stdout.read1(4096) if hasattr(proc.stdout, "read1") else proc.stdout.read(4096)
                        if not data: raise RuntimeError("TLS EOF")
                        if not backend_connected:
                            backend = socket.create_connection((backend_host, backend_port), timeout=TCP_BACKEND_CONNECT_TIMEOUT_SEC)
                            backend.setblocking(False)
                            backend.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            backend_connected = True
                        backend.sendall(data)
                    else:
                        data = backend.recv(4096)
                        if not data: raise RuntimeError("Backend EOF")
                        proc.stdin.write(data)
                        proc.stdin.flush()

        except Exception: pass
        finally:
            try:
                if backend is not None: backend.close()
            except Exception: pass
            _kill_proc(proc, f"kme_{label}_s_server")

def kme_tcp_tls_listener(st: KmeState, ctx: KmeServiceCtx, backend_host: str, backend_port: int, label: str) -> None:
    workers = [
        threading.Thread(target=kme_tcp_tls_port_worker, args=(st, ctx, ctx.port_a, backend_host, backend_port, label), daemon=True),
        threading.Thread(target=kme_tcp_tls_port_worker, args=(st, ctx, ctx.port_b, backend_host, backend_port, label), daemon=True),
    ]
    for t in workers: t.start()
    while not st.stop.is_set(): time.sleep(0.5)

def _json_ok(handler: BaseHTTPRequestHandler, code: int, obj: dict) -> None:
    b = json.dumps(obj).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(b)))
    handler.end_headers()
    handler.wfile.write(b)

class KeySyncHandler(BaseHTTPRequestHandler):
    server_version = "KeySync/2.0"

    def do_POST(self) -> None:
        if self.path != "/keys":
            _json_ok(self, 404, {"ok": False, "error": "not found"})
            return

        ln = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(ln) if ln > 0 else b"{}"

        try: obj = json.loads(raw.decode("utf-8", errors="replace").strip() or "{}")
        except Exception as e:
            _json_ok(self, 400, {"ok": False, "error": f"bad json: {repr(e)}"})
            return

        st: KmeState = self.server.kme_state  # type: ignore[attr-defined]
        op = obj.get("op", "")

        if op == "prefetch":
            kids = [x.get("key_ID", "") for x in obj.get("key_IDs", []) if x.get("key_ID")]
            if kids: st.prefetch_q.put(kids)
            _json_ok(self, 200, {"ok": True, "op": "prefetch"})
            return

        svc = obj.get("service", "")
        ctx = st.udp if svc == "udp" else st.tcp1 if svc == "tcp1" else st.tcp2 if svc == "tcp2" else None
        if ctx is None:
            _json_ok(self, 400, {"ok": False, "error": "unknown service"})
            return

        if op == "prepare":
            kid = obj.get("key_ID", "")
            port = int(obj.get("port", 0))
            if not kid or port <= 0:
                _json_ok(self, 400, {"ok": False, "error": "missing key_ID/port"})
                return
            if not _kme_ensure_dec_key(st, kid):
                _json_ok(self, 503, {"ok": False, "error": "dec_key unavailable"})
                return
            _json_ok(self, 200, {"ok": True, "op": "prepare"})
            return

        if op == "commit":
            kid = obj.get("key_ID", "")
            new_port = int(obj.get("new_port", 0))
            old_port = int(obj.get("old_port", 0))
            grace = float(obj.get("grace", 0.0))
            if not kid or new_port <= 0 or old_port <= 0:
                _json_ok(self, 400, {"ok": False, "error": "missing commit fields"})
                return
            if not _kme_ensure_dec_key(st, kid):
                _json_ok(self, 503, {"ok": False, "error": "dec_key unavailable"})
                return

            with ctx.lock:
                prev_key_id = ctx.active_key_id
                prev_active_port = ctx.active_port
                ctx.active_key_id = kid
                ctx.active_port = new_port
                ctx.retire_port = old_port if grace > 0 else None
                ctx.retire_key_id = prev_key_id if (grace > 0 and old_port == prev_active_port) else None
                ctx.retire_deadline = (time.time() + max(0.0, grace)) if grace > 0 else None

            _json_ok(self, 200, {"ok": True, "op": "commit"})
            return

        _json_ok(self, 400, {"ok": False, "error": "unknown op"})

    def log_message(self, fmt: str, *args) -> None:
        return

def run_kme(tag: str) -> None:
    _ensure_tmp_dir()
    st = KmeState()

    threading.Thread(target=kme_prefetch_worker, args=(st,), daemon=True).start()
    threading.Thread(target=kme_udp_tls_listener, args=(st, st.udp), daemon=True).start()

    threading.Thread(target=kme_tcp_tls_listener, args=(st, st.tcp1, KME_TCP1_BACKEND_HOST, KME_TCP1_BACKEND_PORT, "TCP1"), daemon=True).start()
    threading.Thread(target=kme_tcp_tls_listener, args=(st, st.tcp2, KME_TCP2_BACKEND_HOST, KME_TCP2_BACKEND_PORT, "TCP2"), daemon=True).start()

    httpd = HTTPServer(("0.0.0.0", KEYSYNC_PORT), KeySyncHandler)
    httpd.kme_state = st  # type: ignore[attr-defined]
    
    try: httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt: pass
    finally:
        st.stop.set()
        httpd.server_close()


# =============================================================================
# ================================= main ======================================
# =============================================================================

def _default_out_path(tag: str) -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    return os.path.join(RESULTS_DIR, f"{tag}.csv")

def main() -> None:
    parser = argparse.ArgumentParser(description="QKD-KMS TLS proxy (UDP + 2x TCP) with alternating TLS ports.")
    parser.add_argument("role", choices=["sae", "kme"], help="Run as SAE or KME")
    parser.add_argument("switch_tag", help="3 digits: TCP1 TCP2 UDP; each in {1,2,3}. UDP treats 3 as 1.")
    parser.add_argument("-o", "--out", default=None, help="SAE measurement CSV output path (default: results/<switch_tag>.csv)")
    args = parser.parse_args()

    role = args.role.lower()
    tag = args.switch_tag.strip()

    try: t1, t2, u = _parse_switch_tag(tag)
    except Exception as e:
        print(f"Bad switch_tag: {e}")
        raise SystemExit(2)

    if role == "sae":
        out_csv = args.out if args.out else _default_out_path(tag)
        run_sae(tag, out_csv)
    else:
        run_kme(tag)

if __name__ == "__main__":
    main()