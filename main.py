#!/usr/bin/env python3

import argparse
import csv
import ipaddress
import json
import os
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple

# Optional imports (colorama/tqdm). Program still works if missing.
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _COLOR = True
except Exception:
    _COLOR = False
try:
    from tqdm import tqdm
    _TQDM = True
except Exception:
    _TQDM = False

# Lazy import for scapy (for SYN/flag scans)
def _try_import_scapy():
    try:
        from scapy.all import IP, TCP, sr1, conf
        return IP, TCP, sr1, conf
    except Exception:
        print("[!] Scapy is not available. Install it with `pip install scapy` and run with admin privileges.", file=sys.stderr)
        raise


def _read_list_file(path: str) -> List[str]:
    items: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",") if p.strip()]
            if parts:
                items.extend(parts)
    return items


def _read_ports_file(path: str) -> str:
    items = _read_list_file(path)
    return ",".join(items)


def parse_ports(ports_arg: str) -> List[int]:
    if not ports_arg:
        return []
    if ports_arg.startswith("@"):
        file_path = ports_arg[1:]
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Ports file not found: {file_path}")
        ports_arg = _read_ports_file(file_path)

    ports = set()
    for part in ports_arg.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            start, end = int(a), int(b)
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def parse_targets_arg(arg: str) -> List[str]:
    """Parse host targets string which can be comma list or @file."""
    if not arg:
        return []
    if arg.startswith("@"):
        items = _read_list_file(arg[1:])
    else:
        items = [x.strip() for x in arg.split(",") if x.strip()]
    result: List[str] = []
    for item in items:
        result.extend(expand_targets(item))
    return sorted(set(result))


def expand_targets(target: str) -> List[str]:
    try:
        net = ipaddress.ip_network(target, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        return hosts or [str(net.network_address)]
    except ValueError:
        return [target]


def tcp_connect_scan(host: str, port: int, timeout: float = 1.0, banner: bool = False) -> Tuple[int, str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                info = "open"
                if banner:
                    try:
                        s.sendall(b"\r\n")
                        data = s.recv(128)
                        if data:
                            info += f" | banner: {data.decode(errors='ignore').strip()}"
                    except Exception:
                        pass
                return port, info
            else:
                return port, "closed"
    except socket.timeout:
        return port, "filtered"
    except Exception:
        return port, "filtered"


def tcp_syn_scan(host: str, port: int, timeout: float = 1.0) -> Tuple[int, str]:
    IP, TCP, sr1, conf = _try_import_scapy()
    conf.verb = 0
    pkt = IP(dst=host) / TCP(dport=port, flags="S")
    try:
        resp = sr1(pkt, timeout=timeout)
        if resp is None:
            return port, "filtered"
        if resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            if flags & 0x12 == 0x12:  # SYN/ACK
                return port, "open"
            if flags & 0x04:          # RST
                return port, "closed"
        return port, "filtered"
    except Exception:
        return port, "filtered"


# NEW: TCP NULL/FIN/Xmas/ACK scans (Scapy)
def tcp_flag_scan(host: str, port: int, kind: str, timeout: float = 1.0) -> Tuple[int, str]:
    IP, TCP, sr1, conf = _try_import_scapy()
    conf.verb = 0
    flags_map = {"null": 0, "fin": 0x01, "xmas": 0x29, "ack": 0x10}  # FIN+PSH+URG=0x29
    fl = flags_map[kind]
    pkt = IP(dst=host) / TCP(dport=port, flags=fl)
    try:
        resp = sr1(pkt, timeout=timeout)
        if resp is None:
            # класична інтерпретація: NULL/FIN/Xmas -> open|filtered; ACK -> filtered
            return port, ("open|filtered" if kind in ("null", "fin", "xmas") else "filtered")
        if resp.haslayer(TCP):
            rflags = resp.getlayer(TCP).flags
            if kind in ("null", "fin", "xmas"):
                # Отримали RST -> closed; інакше open|filtered
                return port, ("closed" if (rflags & 0x04) else "open|filtered")
            else:  # ACK
                # ACK-скан: RST => unfiltered; відсутність RST => filtered
                return port, ("unfiltered" if (rflags & 0x04) else "filtered")
        return port, "filtered"
    except Exception:
        return port, "filtered"


def udp_scan(host: str, port: int, timeout: float = 1.0) -> Tuple[int, str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                s.connect((host, port))
            except Exception:
                pass
            try:
                s.send(b"\x00")
            except Exception:
                try:
                    s.sendto(b"\x00", (host, port))
                except Exception:
                    return port, "filtered"
            try:
                _ = s.recv(256)
                return port, "open"
            except ConnectionRefusedError:
                return port, "closed"
            except socket.timeout:
                return port, "open|filtered"
            except Exception:
                return port, "filtered"
    except Exception:
        return port, "filtered"


def _is_open_state(state: str) -> bool:
    # Consider open or open|filtered as "openish" for UDP convenience
    return state.startswith("open")


def scan_host(
    host: str,
    ports: List[int],
    method: str,
    timeout: float,
    banner: bool,
    workers: int,
    show_progress: bool,
    retries: int,
) -> List[Dict[str, Any]]:
    if method == "connect":
        base_scanner = lambda h, p: tcp_connect_scan(h, p, timeout, banner)
        proto = "tcp"
    elif method == "syn":
        base_scanner = lambda h, p: tcp_syn_scan(h, p, timeout)
        proto = "tcp"
    elif method in ("null", "fin", "xmas", "ack"):
        base_scanner = lambda h, p: tcp_flag_scan(h, p, method, timeout)
        proto = "tcp"
    elif method == "udp":
        base_scanner = lambda h, p: udp_scan(h, p, timeout)
        proto = "udp"
    else:
        raise ValueError(f"Unknown method: {method}")

    def scanner_with_retry(h: str, p: int) -> Tuple[int, str]:
        last_state = "filtered"
        attempts = max(0, retries) + 1
        for _ in range(attempts):
            port, state = base_scanner(h, p)
            last_state = state
            if state.startswith("open") or method == "ack":
                break  # early success (or ACK got RST/unfiltered)
        return port, last_state

    results: List[Dict[str, Any]] = []
    lock = threading.Lock()

    pbar = None
    if show_progress and _TQDM:
        pbar = tqdm(total=len(ports), desc=f"{host} [{proto}]", unit="port")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scanner_with_retry, host, p): p for p in ports}
        for fut in as_completed(futures):
            p, state = fut.result()
            with lock:
                results.append({"host": host, "port": p, "proto": proto, "state": state})
            if pbar:
                pbar.update(1)
    if pbar:
        pbar.close()

    results.sort(key=lambda x: x["port"])
    return results


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SUTC")


def _ensure_dir(path: str):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)


def save_outputs(
    results: List[Dict[str, Any]],
    json_out: str = None,
    csv_out: str = None,
    ndjson_out: str = None,
    md_out: str = None,
    out_prefix: str = None,
) -> Tuple[str, str, str, str]:
    os.makedirs("data", exist_ok=True)
    json_path = csv_path = ndjson_path = md_path = None

    # Resolve outputs
    if not (json_out or csv_out or ndjson_out or md_out or out_prefix):
        out_prefix = f"scan_{_timestamp()}"

    if out_prefix:
        json_out = json_out or f"data/{out_prefix}.json"
        csv_out = csv_out or f"data/{out_prefix}.csv"
        ndjson_out = ndjson_out or None  # only if explicitly asked
        md_out = md_out or None          # only if explicitly asked

    if json_out:
        _ensure_dir(json_out)
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        json_path = json_out

    if csv_out:
        _ensure_dir(csv_out)
        with open(csv_out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["host", "port", "proto", "state"])
            for r in results:
                w.writerow([r["host"], r["port"], r["proto"], r["state"]])
        csv_path = csv_out

    if ndjson_out:
        _ensure_dir(ndjson_out)
        with open(ndjson_out, "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        ndjson_path = ndjson_out

    if md_out:
        _ensure_dir(md_out)
        with open(md_out, "w", encoding="utf-8") as f:
            f.write(render_markdown_report(results))
        md_path = md_out

    return json_path, csv_path, ndjson_path, md_path


def _colorize_state(state: str) -> str:
    if not _COLOR:
        return state
    if state.startswith("open"):
        return f"{Fore.GREEN}{state}{Style.RESET_ALL}"
    if state == "closed":
        return f"{Fore.RED}{state}{Style.RESET_ALL}"
    return f"{Fore.YELLOW}{state}{Style.RESET_ALL}"


def print_table(results: List[Dict[str, Any]], open_only: bool = False):
    if not results:
        print("No results.")
        return
    by_host: Dict[str, List[Dict[str, Any]]] = {}
    for r in results:
        if open_only and not _is_open_state(r["state"]):
            continue
        by_host.setdefault(r["host"], []).append(r)

    for host, rows in by_host.items():
        if not rows:
            continue
        print(f"\nHost: {host}")
        print("-" * (6 + len(host)))
        width_port = 6
        print(f"{'PORT':<{width_port}}PROTO  STATE")
        for r in rows:
            state = _colorize_state(r["state"])
            print(f"{r['port']:<{width_port}}{r['proto']:<6}{state}")


def render_markdown_report(results: List[Dict[str, Any]]) -> str:
    if not results:
        return "# Scan Report\n\n_No results._\n"
    header = f"# Scan Report — {datetime.now(timezone.utc).isoformat()}\n\n"
    by_host: Dict[str, List[Dict[str, Any]]] = {}
    for r in results:
        by_host.setdefault(r["host"], []).append(r)
    parts: List[str] = [header]
    for host, rows in by_host.items():
        parts.append(f"## Host: `{host}`\n\n")
        parts.append("| Port | Proto | State |\n|---:|:-----:|:------|\n")
        for r in sorted(rows, key=lambda x: x["port"]):
            parts.append(f"| {r['port']} | {r['proto']} | {r['state']} |\n")
        parts.append("\n")
    return "".join(parts)


def _apply_profiles(args) -> str:
    """Return a ports string constructed from profiles/flags if applicable, else None."""
    profiles = []
    if args.web:
        profiles.append("80,443,8080,8443,8000,8008,8081")
    if args.db:
        profiles.append("1433,1521,3306,5432,6379,27017,5000")
    if profiles:
        return ",".join(profiles)
    return None


def main():
    parser = argparse.ArgumentParser(description="Simple Python Port Scanner (connect(), SYN, UDP, NULL/FIN/Xmas/ACK)")
    parser.add_argument("target", help="Target host/IP or CIDR (e.g., 192.168.1.0/24) or comma list or @file")

    # Port sources
    parser.add_argument("-p", "--ports", default=None, help="Ports, e.g. '80,443,8000-8100' or '@data/list.txt'")
    parser.add_argument("--top1000", action="store_true", help="Use top-1000 TCP preset from data/top1000_tcp.txt")
    parser.add_argument("--web", action="store_true", help="Use a web profile (80,443,8080,8443,...)")
    parser.add_argument("--db", action="store_true", help="Use a database profile (3306,5432,1433,6379,...)")
    parser.add_argument("--exclude-ports", default=None, help="Exclude ports, supports ranges and @file (e.g. '135-139,445' or '@skip.txt')")

    # Method & perf
    parser.add_argument(
        "-m", "--method",
        choices=["connect", "syn", "udp", "null", "fin", "xmas", "ack"],
        default="connect",
        help="Scan method (connect/syn/udp/null/fin/xmas/ack; default: connect)"
    )
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Per-port timeout in seconds (default 1.0)")
    parser.add_argument("-w", "--workers", type=int, default=200, help="Max concurrent workers (default 200)")
    parser.add_argument("--banner", action="store_true", help="Try to grab a short banner on open ports (connect scan only)")
    parser.add_argument("--progress", action="store_true", help="Show a progress bar (requires tqdm)")
    parser.add_argument("--retries", type=int, default=0, help="Retry probes N times before finalizing state (default 0)")

    # Output controls
    parser.add_argument("--open-only", action="store_true", help="Show/save only open ports (and open|filtered for UDP)")
    parser.add_argument("--json-out", default=None, help="Explicit path to JSON output (e.g., data/scan.json)")
    parser.add_argument("--csv-out",  default=None, help="Explicit path to CSV output (e.g., data/scan.csv)")
    parser.add_argument("--ndjson-out", default=None, help="Explicit path to NDJSON output (e.g., data/scan.ndjson)")
    parser.add_argument("--md-out", default=None, help="Explicit path to Markdown report (e.g., reports/scan.md)")
    parser.add_argument("--no-save", action="store_true", help="Do not save any output files")

    parser.add_argument("-o", "--out", default=None, help="Output prefix for files in ./data (default auto with timestamp)")

    # Host exclusions
    parser.add_argument("--exclude-hosts", default=None, help="Exclude hosts/CIDRs (comma list or @file)")

    args = parser.parse_args()

    # Determine which ports we use
    ports_arg = _apply_profiles(args) or args.ports
    if args.top1000 and ports_arg:
        print("[!] Ignoring --top1000 because ports were specified.", file=sys.stderr)
    if args.top1000 and not ports_arg:
        ports_arg = "@data/top1000_tcp.txt"
    if not ports_arg:
        ports_arg = "1-1024"

    ports = parse_ports(ports_arg)

    # Exclude ports if requested
    if args.exclude_ports:
        exclude_ports = set(parse_ports(args.exclude_ports))
        ports = [p for p in ports if p not in exclude_ports]
        if not ports:
            print("[!] After exclusions, no ports left to scan.", file=sys.stderr)
            sys.exit(1)

    # Targets expand (and exclusions)
    all_targets: List[str] = []
    all_targets.extend(parse_targets_arg(args.target))
    if not all_targets:
        print("[!] No valid targets.", file=sys.stderr)
        sys.exit(1)

    if args.exclude_hosts:
        excluded = set(parse_targets_arg(args.exclude_hosts))
        all_targets = [h for h in all_targets if h not in excluded]
        if not all_targets:
            print("[!] After host exclusions, no targets left.", file=sys.stderr)
            sys.exit(1)

    # Banner not applicable for SYN/UDP/flag scans
    if args.method in ("syn", "udp", "null", "fin", "xmas", "ack") and args.banner:
        print("[!] --banner is ignored for this scan method.", file=sys.stderr)

    all_results: List[Dict[str, Any]] = []
    for host in all_targets:
        try:
            socket.gethostbyname(host)
        except Exception:
            pass
        host_results = scan_host(
            host, ports, args.method, args.timeout, args.banner,
            args.workers, args.progress, args.retries
        )
        all_results.extend(host_results)

    # Optional filter before saving/printing
    filtered_results = [r for r in all_results if (not args.open_only or _is_open_state(r["state"]))]

    # Print
    print_table(all_results, open_only=args.open_only)

    # Save
    if not args.no_save:
        json_out = args.json_out
        csv_out = args.csv_out
        ndjson_out = args.ndjson_out
        md_out = args.md_out
        prefix = None if (json_out or csv_out or ndjson_out or md_out) else (args.out or f"scan_{_timestamp()}")
        jp, cp, np, mp = save_outputs(
            filtered_results,
            json_out=json_out, csv_out=csv_out, ndjson_out=ndjson_out, md_out=md_out, out_prefix=prefix
        )
        saved = " and ".join(p for p in [jp, cp, np, mp] if p)
        if saved:
            print(f"\nSaved: {saved}")
    else:
        print("\n(No files saved; use --json-out/--csv-out/--ndjson-out/--md-out or -o PREFIX to save results.)")


if __name__ == "__main__":
    main()
