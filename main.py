#!/usr/bin/env python3
"""
Simple Port Scanner v0.3
- TCP connect() (default), TCP SYN (--method syn), UDP (--method udp)
- Top-1000 preset (--top1000) and -p @file
- NEW in v0.3:
  * --open-only           : show/save only open ports (or open|filtered for UDP)
  * Colored console output (requires colorama on Windows)
  * Progress bar via tqdm
  * --json-out / --csv-out: explicit output paths; --no-save to skip files
  * Port profiles         : --web, --db
"""

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

# Lazy import for scapy (only for --method syn)
def _try_import_scapy():
    try:
        from scapy.all import IP, TCP, sr1, conf
        return IP, TCP, sr1, conf
    except Exception as e:
        print("[!] Scapy is not available. Install it with `pip install scapy` and run with admin privileges.", file=sys.stderr)
        raise

def _read_ports_file(path: str) -> str:
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",") if p.strip()]
            if parts:
                items.extend(parts)
            else:
                items.append(line)
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
    pkt = IP(dst=host)/TCP(dport=port, flags="S")
    try:
        resp = sr1(pkt, timeout=timeout)
        if resp is None:
            return port, "filtered"
        if resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            if flags & 0x12 == 0x12:
                return port, "open"
            if flags & 0x04:
                return port, "closed"
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

def scan_host(host: str, ports: List[int], method: str, timeout: float, banner: bool, workers: int, show_progress: bool) -> List[Dict[str, Any]]:
    if method == "connect":
        scanner = lambda h, p: tcp_connect_scan(h, p, timeout, banner)
        proto = "tcp"
    elif method == "syn":
        scanner = lambda h, p: tcp_syn_scan(h, p, timeout)
        proto = "tcp"
    elif method == "udp":
        scanner = lambda h, p: udp_scan(h, p, timeout)
        proto = "udp"
    else:
        raise ValueError(f"Unknown method: {method}")

    results = []
    lock = threading.Lock()

    pbar = None
    if show_progress and _TQDM:
        pbar = tqdm(total=len(ports), desc=f"{host} [{proto}]", unit="port")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scanner, host, p): p for p in ports}
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

def save_outputs(results: List[Dict[str, Any]], json_out: str = None, csv_out: str = None, out_prefix: str = None) -> Tuple[str, str]:
    os.makedirs("data", exist_ok=True)
    json_path = None
    csv_path = None

    # Resolve outputs
    if not (json_out or csv_out or out_prefix):
        out_prefix = f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%SUTC')}"

    if out_prefix and not json_out:
        json_out = f"data/{out_prefix}.json"
    if out_prefix and not csv_out:
        csv_out = f"data/{out_prefix}.csv"

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        json_path = json_out

    if csv_out:
        with open(csv_out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["host", "port", "proto", "state"])
            for r in results:
                w.writerow([r["host"], r["port"], r["proto"], r["state"]])
        csv_path = csv_out

    return json_path, csv_path

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
    parser = argparse.ArgumentParser(description="Simple Python Port Scanner (connect(), SYN, UDP)")
    parser.add_argument("target", help="Target host/IP or CIDR (e.g., 192.168.1.0/24)")

    # Port sources
    parser.add_argument("-p", "--ports", default=None, help="Ports, e.g. '80,443,8000-8100' or '@data/list.txt'")
    parser.add_argument("--top1000", action="store_true", help="Use top-1000 TCP preset from data/top1000_tcp.txt")
    parser.add_argument("--web", action="store_true", help="Use a web profile (80,443,8080,8443,...)")
    parser.add_argument("--db", action="store_true", help="Use a database profile (3306,5432,1433,6379,...)")

    # Method & perf
    parser.add_argument("-m", "--method", choices=["connect", "syn", "udp"], default="connect", help="Scan method (default: connect)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Per-port timeout in seconds (default 1.0)")
    parser.add_argument("-w", "--workers", type=int, default=200, help="Max concurrent workers (default 200)")
    parser.add_argument("--banner", action="store_true", help="Try to grab a short banner on open ports (connect scan only)")
    parser.add_argument("--progress", action="store_true", help="Show a progress bar (requires tqdm)")

    # Output controls
    parser.add_argument("--open-only", action="store_true", help="Show/save only open ports (and open|filtered for UDP)")
    parser.add_argument("--json-out", default=None, help="Explicit path to JSON output (e.g., data/scan.json)")
    parser.add_argument("--csv-out",  default=None, help="Explicit path to CSV output (e.g., data/scan.csv)")
    parser.add_argument("--no-save", action="store_true", help="Do not save any output files")

    parser.add_argument("-o", "--out", default=None, help="Output prefix for files in ./data (default auto with timestamp)")

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
    targets = expand_targets(args.target)

    if args.method in ("syn", "udp") and args.banner:
        print("[!] --banner is ignored for this scan method.", file=sys.stderr)

    all_results: List[Dict[str, Any]] = []
    for host in targets:
        try:
            socket.gethostbyname(host)
        except Exception:
            pass
        host_results = scan_host(host, ports, args.method, args.timeout, args.banner, args.workers, args.progress)
        all_results.extend(host_results)

    # Optional filter before saving/printing
    filtered_results = [r for r in all_results if (not args.open_only or _is_open_state(r["state"]))]

    # Print
    print_table(all_results, open_only=args.open_only)

    # Save
    if not args.no_save:
        json_out = args.json_out
        csv_out = args.csv_out
        prefix = None if (json_out or csv_out) else (args.out or f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%SUTC')}")
        jp, cp = save_outputs(filtered_results, json_out=json_out, csv_out=csv_out, out_prefix=prefix)
        saved = " and ".join(p for p in [jp, cp] if p)
        if saved:
            print(f"\nSaved: {saved}")
    else:
        print("\n(No files saved; use --json-out/--csv-out or -o PREFIX to save results.)")

if __name__ == "__main__":
    main()
