#!/usr/bin/env python3

import json
import os
import threading
import time
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Tuple, Any, List

from scapy.all import sniff, Ether, IP, TCP, UDP
from flask import Flask, jsonify
from urllib import request, error as urlerror

INTERFACES = ["vmon-eth0", "vmon-eth1"]

PACKET_LOG_FILE = "/tmp/vmon_packets.log"
METRICS_FILE = "/tmp/vmon_metrics.json"

FLUSH_INTERVAL_SECONDS = 5

CONTROLLER_PUSH_URL = os.getenv("VMON_CONTROLLER_URL")

FlowKey = Tuple[str, str, str, int, int]

flows: Dict[FlowKey, Dict[str, Any]] = {}
flows_lock = threading.Lock()

pending_syn: Dict[Tuple[str, str, int, int], float] = {}
pending_syn_lock = threading.Lock()

app = Flask(__name__)

log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)
app.logger.setLevel(logging.ERROR)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec = "microseconds")

def now_epoch() -> float:
    return time.time()

def log_packet_line(line: str) -> None:
    try:
        with open(PACKET_LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass

def log_internal(line: str) -> None:
    try:
        with open("/tmp/vmon_internal.log", "a") as f:
            f.write(f"[{now_iso()}] {line}\n")
    except Exception:
        pass

def classify_direction(src_port: int, dst_port: int) -> str:
    server_ports = {80, 81, 443, 53, 8080, 8000}
    if dst_port in server_ports and src_port not in server_ports:
        return "client_to_server"
    if src_port in server_ports and dst_port not in server_ports:
        return "server_to_client"
    return "unknown"

def ensure_flow_entry(
    proto: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    iface: Optional[str] = None,
) -> FlowKey:
    key: FlowKey = (proto, src_ip, dst_ip, src_port, dst_port)
    ts_iso = now_iso()
    ts_epoch = now_epoch()

    if key not in flows:
        flows[key] = {
            "proto": proto,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "direction": classify_direction(src_port, dst_port),
            "packets": 0,
            "bytes": 0,
            "first_seen": ts_iso,
            "last_seen": ts_iso,
            "first_seen_epoch": ts_epoch,
            "last_seen_epoch": ts_epoch,
            "tcp_syn": 0,
            "tcp_synack": 0,
            "tcp_fin": 0,
            "tcp_rst": 0,
            "syn_rtt_ms": None,
            "first_iface": iface,
            "last_iface": iface,
        }

    return key

def update_flow_stats(
    proto: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    length: int,
    tcp_flags: Optional[int] = None,
    iface: Optional[str] = None,
) -> None:
    with flows_lock:
        key = ensure_flow_entry(proto, src_ip, dst_ip, src_port, dst_port, iface)
        entry = flows[key]

        entry["packets"] += 1
        entry["bytes"] += int(length)

        ts_iso = now_iso()
        ts_epoch = now_epoch()

        entry["last_seen"] = ts_iso
        entry["last_seen_epoch"] = ts_epoch

        if iface is not None:
            if entry.get("first_iface") is None:
                entry["first_iface"] = iface
            entry["last_iface"] = iface

        if proto == "TCP" and tcp_flags is not None:
            syn = bool(tcp_flags & 0x02)
            ack = bool(tcp_flags & 0x10)
            fin = bool(tcp_flags & 0x01)
            rst = bool(tcp_flags & 0x04)

            if syn and not ack:
                entry["tcp_syn"] += 1
            if syn and ack:
                entry["tcp_synack"] += 1
            if fin:
                entry["tcp_fin"] += 1
            if rst:
                entry["tcp_rst"] += 1

def track_tcp_syn_rtt(
    ip_src: str,
    ip_dst: str,
    sport: int,
    dport: int,
    flags: int,
) -> None:
    ts = now_epoch()

    syn_only = bool(flags & 0x02) and not bool(flags & 0x10)
    syn_ack = bool(flags & 0x02) and bool(flags & 0x10)

    syn_key = (ip_src, ip_dst, sport, dport)
    rev_key = (ip_dst, ip_src, dport, sport)

    with pending_syn_lock:
        if syn_only:
            pending_syn[syn_key] = ts
        elif syn_ack:
            if rev_key in pending_syn:
                t_syn = pending_syn.pop(rev_key)
                rtt_ms = (ts - t_syn) * 1000.0
                with flows_lock:
                    flow_key = ensure_flow_entry(
                        "TCP",
                        ip_dst,
                        ip_src,
                        dport,
                        sport,
                        iface = None,
                    )
                    entry = flows[flow_key]
                    if entry["syn_rtt_ms"] is None or rtt_ms < entry["syn_rtt_ms"]:
                        entry["syn_rtt_ms"] = rtt_ms

def handle_packet(pkt) -> None:
    if not pkt.haslayer(Ether):
        return
    
    iface = getattr(pkt, "sniffed_on", None)

    eth = pkt[Ether]
    length = len(pkt)

    line_parts: List[str] = [
        now_iso(),
        f"ETH {eth.src} TO {eth.dst}",
        f"TYPE = 0x{eth.type:04x}",
        f"LEN = {length}",
    ]

    if iface is not None:
        line_parts.append(f"IFACE = {iface}")

    if pkt.haslayer(IP):
        ip = pkt[IP]
        line_parts.append(f"IP {ip.src} TO {ip.dst} PROTO = {ip.proto}")

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags_int = int(tcp.flags)
            line_parts.append(f"TCP {tcp.sport} TO {tcp.dport} FLAGS = {flags_int}")
            update_flow_stats(
                proto = "TCP",
                src_ip = ip.src,
                dst_ip = ip.dst,
                src_port = int(tcp.sport),
                dst_port = int(tcp.dport),
                length = length,
                tcp_flags = flags_int,
                iface = iface,
            )
            track_tcp_syn_rtt(ip.src, ip.dst, int(tcp.sport), int(tcp.dport), flags_int)

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            line_parts.append(f"UDP {udp.sport} TO {udp.dport}")
            update_flow_stats(
                proto = "UDP",
                src_ip = ip.src,
                dst_ip = ip.dst,
                src_port = int(udp.sport),
                dst_port = int(udp.dport),
                length = length,
                iface = iface,
            )
        else:
            update_flow_stats(
                proto = f"IP: {ip.proto}",
                src_ip = ip.src,
                dst_ip = ip.dst,
                src_port = 0,
                dst_port = 0,
                length = length,
                iface = iface,
            )

    log_packet_line(" | ".join(line_parts))

def compute_derived_metrics(entry: Dict[str, Any]) -> Dict[str, Any]:
    first_ts = entry.get("first_seen_epoch", entry.get("last_seen_epoch", now_epoch()))
    last_ts = entry.get("last_seen_epoch", first_ts)
    duration = max(last_ts - first_ts, 0.000001)

    packets = entry.get("packets", 0)
    bytes_ = entry.get("bytes", 0)

    pps = packets / duration
    bps = (bytes_ * 8) / duration

    out = {
        k: v
        for k, v in entry.items()
        if k not in ("first_seen_epoch", "last_seen_epoch")
    }
    out["duration_seconds"] = duration
    out["pps"] = pps
    out["bps"] = bps

    return out

def build_metrics_payload() -> Dict[str, Any]:
    with flows_lock:
        snapshot = [compute_derived_metrics(data) for data in flows.values()]

    payload: Dict[str, Any] = {
        "generated_at": now_iso(),
        "flow_count": len(snapshot),
        "flows": snapshot,
    }
    return payload

def push_metrics_to_controller(payload: Dict[str, Any]) -> None:
    if not CONTROLLER_PUSH_URL:
        return

    try:
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            CONTROLLER_PUSH_URL,
            data = data,
            headers = {"Content-Type": "application/json"},
            method = "POST",
        )
        request.urlopen(req, timeout = 1.0).read()
    except urlerror.URLError as e:
        log_internal(f"ERROR SENDING TO CONTROLLER ({CONTROLLER_PUSH_URL}): {e}")
    except Exception as e:
        log_internal(f"EXCEPTION SENDING TO CONTROLLER: {e}")

def metrics_flush_loop(interval_seconds: int = FLUSH_INTERVAL_SECONDS) -> None:
    while True:
        time.sleep(interval_seconds)
        payload = build_metrics_payload()
        try:
            with open(METRICS_FILE, "w") as f:
                json.dump(payload, f, indent = 2)
        except Exception as e:
            log_internal(f"ERROR WRITING METRICS_FILE: {e}")
        push_metrics_to_controller(payload)

def sniff_loop() -> None:
    sniff(
        iface = INTERFACES,
        prn = handle_packet,
        store = False,
    )

@app.route("/metrics", methods = ["GET"])
def http_metrics():
    payload = build_metrics_payload()
    return jsonify(payload)

@app.route("/health", methods = ["GET"])
def http_health():
    return jsonify({"status": "OK", "time": now_iso()})

def main() -> None:
    t_flush = threading.Thread(target = metrics_flush_loop, daemon = True)
    t_flush.start()

    t_sniff = threading.Thread(target = sniff_loop, daemon = True)
    t_sniff.start()

    port = int(os.getenv("VMON_HTTP_PORT", "5000"))
    app.run(
        host = "0.0.0.0",
        port = port,
        debug = False,
        use_reloader = False,
    )

if __name__ == "__main__":
    main()