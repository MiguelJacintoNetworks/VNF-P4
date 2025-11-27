#!/usr/bin/env python3

import math
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

IPERF_PORT: str = "5001"

BACKEND_IPS: Set[str] = {"10.0.4.2", "10.0.5.2", "10.0.6.2"}

FIELDS: List[str] = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "frame.len",
    "tcp.seq",
    "tcp.ack",
    "tcp.flags",
    "tcp.analysis.ack_rtt",
    "tcp.analysis.retransmission",
    "tcp.time_delta",
    "tcp.len",
]

def run_tshark(pcap: str) -> List[Dict[str, str]]:
    command: List[str] = [
        "tshark",
        "-r",
        pcap,
        "-T",
        "fields",
        "-E",
        "separator=;",
    ]
    for field in FIELDS:
        command += ["-e", field]

    proc = subprocess.run(
        command,
        text = True,
        capture_output = True,
    )

    if proc.returncode != 0:
        print(f"WARNING: TSHARK RETURNED {proc.returncode} FOR {pcap}", file=sys.stderr)
        if proc.stderr:
            print(proc.stderr.strip(), file=sys.stderr)
        if not proc.stdout:
            return []

    output = proc.stdout
    lines = [line for line in output.splitlines() if line.strip()]
    rows: List[Dict[str, str]] = []

    for line in lines:
        columns = line.split(";")
        if len(columns) < len(FIELDS):
            columns += [""] * (len(FIELDS) - len(columns))
        row = dict(zip(FIELDS, columns))
        rows.append(row)

    return rows

def to_float(value: str) -> Optional[float]:
    try:
        return float(value)
    except Exception:
        return None

def to_int(value: str) -> int:
    try:
        return int(value)
    except Exception:
        return 0

def format_cell(text: Any, width: int, align: str = "right") -> str:
    content = str(text)
    if len(content) > width:
        content = content[:width]
    if align == "right":
        return content.rjust(width)
    return content.ljust(width)

def main() -> None:
    if len(sys.argv) < 2:
        pcaps: List[str] = ["vlb-eth1.pcap", "vlb-eth2.pcap", "vlb-eth3.pcap"]
    else:
        pcaps: List[str] = sys.argv[1:]

    flows: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

    backend_stats: Dict[str, Dict[str, Any]] = {}
    for ip in BACKEND_IPS:
        backend_stats[ip] = {
            "first_t": None,
            "last_t": None,
            "packets": 0,
            "bytes": 0,
            "sum_dt": 0.0,
            "sum_dt2": 0.0,
            "dt_count": 0,
            "rtt_min": None,
            "rtt_max": None,
            "rtt_sum": 0.0,
            "rtt_count": 0,
            "retx": 0,
            "flows": set(),
        }

    total_packets: int = 0

    for pcap in pcaps:
        print(f"PROCESSING: {pcap}")
        rows = run_tshark(pcap)

        for row in rows:
            src = row["ip.src"]
            dst = row["ip.dst"]
            sport = row["tcp.srcport"]
            dport = row["tcp.dstport"]

            if not sport and not dport:
                continue

            if sport != IPERF_PORT and dport != IPERF_PORT:
                continue

            timestamp = to_float(row["frame.time_epoch"])
            if timestamp is None:
                continue

            length = to_int(row["frame.len"])
            dt = to_float(row["tcp.time_delta"])
            rtt = to_float(row["tcp.analysis.ack_rtt"])
            retransmission_flag = bool(row["tcp.analysis.retransmission"])

            key = (src, sport, dst, dport)

            if key not in flows:
                flows[key] = {
                    "first_t": timestamp,
                    "last_t": timestamp,
                    "packets": 0,
                    "bytes": 0,
                    "sum_dt": 0.0,
                    "sum_dt2": 0.0,
                    "dt_count": 0,
                    "rtt_min": None,
                    "rtt_max": None,
                    "rtt_sum": 0.0,
                    "rtt_count": 0,
                    "retx": 0,
                }

            flow_metrics = flows[key]
            flow_metrics["packets"] += 1
            flow_metrics["bytes"] += length
            total_packets += 1

            if timestamp < flow_metrics["first_t"]:
                flow_metrics["first_t"] = timestamp
            if timestamp > flow_metrics["last_t"]:
                flow_metrics["last_t"] = timestamp

            if dt is not None:
                flow_metrics["sum_dt"] += dt
                flow_metrics["sum_dt2"] += dt * dt
                flow_metrics["dt_count"] += 1

            if rtt is not None:
                flow_metrics["rtt_sum"] += rtt
                flow_metrics["rtt_count"] += 1
                if flow_metrics["rtt_min"] is None or rtt < flow_metrics["rtt_min"]:
                    flow_metrics["rtt_min"] = rtt
                if flow_metrics["rtt_max"] is None or rtt > flow_metrics["rtt_max"]:
                    flow_metrics["rtt_max"] = rtt

            if retransmission_flag:
                flow_metrics["retx"] += 1

            backend_ip: Optional[str] = None
            if dport == IPERF_PORT:
                backend_ip = dst
            elif sport == IPERF_PORT:
                backend_ip = src

            if backend_ip in backend_stats:
                backend_metrics = backend_stats[backend_ip]

                if backend_metrics["first_t"] is None or timestamp < backend_metrics["first_t"]:
                    backend_metrics["first_t"] = timestamp
                if backend_metrics["last_t"] is None or timestamp > backend_metrics["last_t"]:
                    backend_metrics["last_t"] = timestamp

                backend_metrics["packets"] += 1
                backend_metrics["bytes"] += length
                backend_metrics["flows"].add(key)

                if dt is not None:
                    backend_metrics["sum_dt"] += dt
                    backend_metrics["sum_dt2"] += dt * dt
                    backend_metrics["dt_count"] += 1

                if rtt is not None:
                    backend_metrics["rtt_sum"] += rtt
                    backend_metrics["rtt_count"] += 1
                    if backend_metrics["rtt_min"] is None or rtt < backend_metrics["rtt_min"]:
                        backend_metrics["rtt_min"] = rtt
                    if backend_metrics["rtt_max"] is None or rtt > backend_metrics["rtt_max"]:
                        backend_metrics["rtt_max"] = rtt

                if retransmission_flag:
                    backend_metrics["retx"] += 1

    if not flows:
        print(f"NO TCP IPERF FLOWS (PORT {IPERF_PORT}) FOUND IN PCAPS.")
        sys.exit(0)

    headers: List[str] = [
        "SRC_IP",
        "DST_IP",
        "SPORT",
        "DPORT",
        "PKTS",
        "BYTES",
        "DURATION (S)",
        "PPS",
        "MBPS",
        "RETRANSMISSIONS",
        "RTT_AVG (MS)",
        "RTT_MIN (MS)",
        "RTT_MAX (MS)",
        "JITTER (MS)",
    ]

    col_widths: List[int] = [len(header) for header in headers]
    rows_out: List[List[str]] = []

    sorted_flows = sorted(
        flows.items(),
        key = lambda item: item[1]["bytes"],
        reverse = True,
    )

    for key, flow_metrics in sorted_flows:
        src, sport, dst, dport = key

        duration = max(flow_metrics["last_t"] - flow_metrics["first_t"], 1e-6)
        pps = flow_metrics["packets"] / duration
        mbps = (flow_metrics["bytes"] * 8) / duration / 1e6

        if flow_metrics["rtt_count"] > 0:
            rtt_avg = (flow_metrics["rtt_sum"] / flow_metrics["rtt_count"]) * 1000.0
            rtt_min = flow_metrics["rtt_min"] * 1000.0
            rtt_max = flow_metrics["rtt_max"] * 1000.0
        else:
            rtt_avg = rtt_min = rtt_max = None

        if flow_metrics["dt_count"] > 1:
            mean_dt = flow_metrics["sum_dt"] / flow_metrics["dt_count"]
            mean_dt2 = flow_metrics["sum_dt2"] / flow_metrics["dt_count"]
            variance_dt = max(mean_dt2 - mean_dt * mean_dt, 0.0)
            jitter_ms = math.sqrt(variance_dt) * 1000.0
        else:
            jitter_ms = None

        row: List[str] = [
            src,
            dst,
            str(sport),
            str(dport),
            str(flow_metrics["packets"]),
            str(flow_metrics["bytes"]),
            f"{duration:.3f}",
            f"{pps:.2f}",
            f"{mbps:.3f}",
            str(flow_metrics["retx"]),
            "-" if rtt_avg is None else f"{rtt_avg:.3f}",
            "-" if rtt_min is None else f"{rtt_min:.3f}",
            "-" if rtt_max is None else f"{rtt_max:.3f}",
            "-" if jitter_ms is None else f"{jitter_ms:.3f}",
        ]

        rows_out.append(row)
        for index, cell in enumerate(row):
            col_widths[index] = max(col_widths[index], len(cell))

    def format_row(cells: List[str]) -> str:
        return "  ".join(
            cell.ljust(col_widths[index]) for index, cell in enumerate(cells)
        )

    print("\nTCP IPERF FLOW METRICS (PORT {})\n".format(IPERF_PORT))
    print(format_row(headers))
    print("-" * (sum(col_widths) + 2 * (len(col_widths) - 1)))

    for row in rows_out:
        print(format_row(row))

    print("\nTOTAL FLOWS : {}".format(len(flows)))
    print("TOTAL BYTES : {}".format(sum(flow["bytes"] for flow in flows.values())))
    print("TOTAL PKTS  : {}".format(total_packets))
    print()

    backend_headers: List[str] = [
        "BACKEND_IP",
        "FLOWS",
        "PKTS",
        "BYTES",
        "DURATION (S)",
        "PPS",
        "MBPS",
        "RETRANSMISSIONS",
        "RTT_AVG (MS)",
        "RTT_MIN (MS)",
        "RTT_MAX (MS)",
        "JITTER (MS)",
    ]

    backend_col_widths: List[int] = [len(header) for header in backend_headers]
    backend_rows_out: List[List[str]] = []

    for backend_ip in sorted(BACKEND_IPS):
        backend_metrics = backend_stats[backend_ip]

        if (
            backend_metrics["first_t"] is None
            or backend_metrics["last_t"] is None
            or backend_metrics["packets"] == 0
        ):
            row_backend: List[str] = [
                backend_ip,
                "0",
                "0",
                "0",
                "-",
                "-",
                "-",
                "0",
                "-",
                "-",
                "-",
                "-",
            ]
        else:
            duration_b = max(
                backend_metrics["last_t"] - backend_metrics["first_t"],
                1e-6,
            )
            pps_b = backend_metrics["packets"] / duration_b
            mbps_b = (backend_metrics["bytes"] * 8) / duration_b / 1e6

            if backend_metrics["rtt_count"] > 0:
                rtt_avg_b = (
                    backend_metrics["rtt_sum"] / backend_metrics["rtt_count"]
                ) * 1000.0
                rtt_min_b = backend_metrics["rtt_min"] * 1000.0
                rtt_max_b = backend_metrics["rtt_max"] * 1000.0
            else:
                rtt_avg_b = rtt_min_b = rtt_max_b = None

            if backend_metrics["dt_count"] > 1:
                mean_dt_b = backend_metrics["sum_dt"] / backend_metrics["dt_count"]
                mean_dt2_b = backend_metrics["sum_dt2"] / backend_metrics["dt_count"]
                variance_dt_b = max(mean_dt2_b - mean_dt_b * mean_dt_b, 0.0)
                jitter_ms_b = math.sqrt(variance_dt_b) * 1000.0
            else:
                jitter_ms_b = None

            row_backend = [
                backend_ip,
                str(len(backend_metrics["flows"])),
                str(backend_metrics["packets"]),
                str(backend_metrics["bytes"]),
                f"{duration_b:.3f}",
                f"{pps_b:.2f}",
                f"{mbps_b:.3f}",
                str(backend_metrics["retx"]),
                "-" if rtt_avg_b is None else f"{rtt_avg_b:.3f}",
                "-" if rtt_min_b is None else f"{rtt_min_b:.3f}",
                "-" if rtt_max_b is None else f"{rtt_max_b:.3f}",
                "-" if jitter_ms_b is None else f"{jitter_ms_b:.3f}",
            ]

        backend_rows_out.append(row_backend)
        for index, cell in enumerate(row_backend):
            backend_col_widths[index] = max(backend_col_widths[index], len(cell))

    def format_backend_row(cells: List[str]) -> str:
        return "  ".join(
            cell.ljust(backend_col_widths[index])
            for index, cell in enumerate(cells)
        )

    print("TCP IPERF BACKEND METRICS (PORT {})\n".format(IPERF_PORT))
    print(format_backend_row(backend_headers))
    print("-" * (sum(backend_col_widths) + 2 * (len(backend_col_widths) - 1)))

    for row_backend in backend_rows_out:
        print(format_backend_row(row_backend))

    print()
    print("LEGEND PER BACKEND:")
    print("  FLOWS               - NUMBER OF DISTINCT TCP FLOWS USING THIS BACKEND")
    print("  DURATION (S)        - TOTAL TIME WINDOW WITH TRAFFIC FOR THIS BACKEND")
    print("  PPS                 - AGGREGATED PACKETS PER SECOND")
    print("  MBPS                - AVERAGE THROUGHPUT FOR THIS BACKEND")
    print("  RETRANSMISSIONS     - NUMBER OF TCP RETRANSMISSIONS")
    print("  RTT                 - AVERAGE/MIN/MAX RTT BASED ON ACKS")
    print("  JITTER (MS)         - STANDARD DEVIATION OF INTER-PACKET TIME (TCP.TIME_DELTA)")


if __name__ == "__main__":
    main()
