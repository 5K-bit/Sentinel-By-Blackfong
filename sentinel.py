#!/usr/bin/env python3
"""BLACKFONG SENTINEL — recovered and hardened local security monitor."""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from uuid import uuid4
from datetime import datetime
from pathlib import Path
from typing import Optional

APP_NAME = "BLACKFONG SENTINEL"
APP_VERSION = "2.1.0-recovered"

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORT_DIR = BASE_DIR / "reports"
EXPORT_DIR = BASE_DIR / "exports"
LOG_DIR = BASE_DIR / "logs"
DB_PATH = DATA_DIR / "sentinel.db"

for directory in (DATA_DIR, REPORT_DIR, EXPORT_DIR, LOG_DIR):
    directory.mkdir(parents=True, exist_ok=True)
    try:
        directory.chmod(0o700)
    except OSError:
        pass

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


class Color:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"


def _c(color: str, text: str) -> str:
    return f"{color}{text}{Color.RESET}"


def info(text: str): print(_c(Color.BLUE, f"[~] {text}"))
def good(text: str): print(_c(Color.GREEN, f"[+] {text}"))
def warn(text: str): print(_c(Color.YELLOW, f"[!] {text}"))
def alert(text: str): print(_c(Color.RED, f"[X] {text}"))
def dim(text: str): print(_c(Color.DIM, f"    {text}"))


def title(text: str):
    width = 60
    border = "─" * width
    print(f"\n{Color.BOLD}{Color.CYAN}┌{border}┐")
    print(f"│  {text:<{width - 2}}│")
    print(f"└{border}┘{Color.RESET}\n")


def section(text: str):
    print(f"\n{Color.BOLD}{Color.BLUE}── {text} ──{Color.RESET}\n")


def setup_logging(verbose: bool = False) -> logging.Logger:
    log_file = LOG_DIR / f"sentinel_{datetime.now().strftime('%Y%m%d')}.log"
    level = logging.DEBUG if verbose else logging.INFO
    file_handler = logging.FileHandler(log_file)
    try:
        log_file.chmod(0o600)
    except OSError:
        pass
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[file_handler, logging.StreamHandler(sys.stdout)],
    )
    return logging.getLogger("sentinel")


logger = logging.getLogger("sentinel")


def confirm(prompt: str) -> bool:
    return input(f"{Color.YELLOW}[?] {prompt} [y/N]: {Color.RESET}").strip().lower() in {"y", "yes"}


def run_command(command: list[str], timeout: int = 30, require_root: bool = False) -> tuple[str, bool]:
    if require_root and not IS_ROOT:
        warn(f"Command '{command[0]}' may need root privileges. Results may be incomplete.")
    if not shutil.which(command[0]):
        return f"[not found] '{command[0]}' is not installed or not in PATH.", False
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        output = result.stdout or result.stderr or ""
        return output, result.returncode == 0
    except subprocess.TimeoutExpired:
        return f"[timeout] Command exceeded {timeout}s.", False
    except Exception as exc:
        logger.exception("Command failed: %s", command)
        return f"[error] {exc}", False


DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT,
    ports_json TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    timestamp TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    message TEXT NOT NULL,
    resolved INTEGER DEFAULT 0
);
"""

EXPECTED_COLUMNS = {
    "scans": {
        "ports_json": "TEXT",
    },
    "alerts": {
        "resolved": "INTEGER DEFAULT 0",
    },
}


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    try:
        DB_PATH.chmod(0o600)
    except OSError:
        pass
    conn.row_factory = sqlite3.Row
    return conn


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def init_db():
    """Create the current schema and migrate older Sentinel databases in-place."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(DB_SCHEMA)
        for table, columns in EXPECTED_COLUMNS.items():
            existing = _table_columns(conn, table)
            for column, definition in columns.items():
                if column not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
                    logger.info("Migrated DB: added %s.%s", table, column)
        conn.commit()


def save_finding(scan_id: Optional[int], category: str, severity: str, detail: str):
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO findings (scan_id, timestamp, category, severity, detail) VALUES (?,?,?,?,?)",
            (scan_id, datetime.now().isoformat(timespec="seconds"), category, severity, detail),
        )


def save_alert(source: str, message: str):
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO alerts (timestamp, source, message, resolved) VALUES (?,?,?,0)",
            (datetime.now().isoformat(timespec="seconds"), source, message),
        )
    logger.warning("ALERT [%s]: %s", source, message)


HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$|^localhost$")


def validate_target(target: str) -> str:
    target = target.strip()
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    if HOST_RE.fullmatch(target):
        return target
    raise ValueError("Target must be localhost, an IPv4/IPv6 address or CIDR, or a valid hostname.")


def validate_port_spec(port_spec: str) -> str:
    port_spec = port_spec.strip()
    if not port_spec:
        raise ValueError("Port specification cannot be empty.")
    for item in port_spec.split(","):
        item = item.strip()
        bounds = item.split("-")
        if len(bounds) > 2 or any(not bound.isdigit() for bound in bounds):
            raise ValueError("Ports must be comma-separated numbers or ranges from 1 to 65535.")
        start = int(bounds[0])
        end = int(bounds[-1])
        if not 1 <= start <= 65535 or not 1 <= end <= 65535 or start > end:
            raise ValueError("Ports must be comma-separated numbers or ranges from 1 to 65535.")
    return port_spec


def get_ip() -> str:
    out, ok = run_command(["hostname", "-I"])
    return out.strip() if ok and out.strip() else "Unknown"


def show_status():
    title(f"{APP_NAME}  v{APP_VERSION}")
    print(f"  User      : {os.getenv('USER', 'unknown')}")
    print(f"  Machine   : {platform.node()}")
    print(f"  OS        : {platform.system()} {platform.release()}")
    print(f"  IP        : {get_ip()}")
    print(f"  Root      : {'Yes' if IS_ROOT else 'No'}")
    print(f"  DB        : {DB_PATH}")
    print()


RISKY_PORTS = {
    "21": ("FTP", "warn", "Cleartext file transfer — prefer SFTP."),
    "22": ("SSH", "info", "Remote terminal — prefer key-based authentication."),
    "23": ("Telnet", "alert", "Cleartext terminal service."),
    "80": ("HTTP", "warn", "Unencrypted web traffic."),
    "443": ("HTTPS", "good", "Encrypted web traffic."),
    "445": ("SMB", "alert", "File-sharing exposure; verify scope and access controls."),
    "3389": ("RDP/XRDP", "warn", "Remote desktop exposure; verify authentication and firewall rules."),
    "8080": ("HTTP-alt", "warn", "Common development/proxy web service."),
}


def show_ports():
    title("OPEN LISTENING PORTS")
    out, ok = run_command(["ss", "-tulpn"], require_root=True)
    if not ok:
        warn("Could not fully retrieve port information.")
    print(out)
    section("SENTINEL INTERPRETATION")
    found = False
    for port, (service, level, note) in RISKY_PORTS.items():
        if re.search(rf":{re.escape(port)}(?:\s|$)", out):
            found = True
            fn = {"info": info, "good": good, "warn": warn, "alert": alert}[level]
            fn(f"[:{port}] {service} — {note}")
    if not found:
        dim("No Sentinel-tracked common ports detected in the current output.")


def parse_nmap_ports(nmap_output: str) -> list[dict]:
    ports: list[dict] = []
    pattern = re.compile(r"^(\d+)/(tcp|udp)\s+(open\S*)\s+(\S+)(?:\s+(.*))?$")
    for raw in nmap_output.splitlines():
        match = pattern.match(raw.strip())
        if not match:
            continue
        port, proto, state, service, version = match.groups()
        ports.append({
            "port": port,
            "protocol": proto,
            "state": state,
            "service": service,
            "version": version or "",
        })
    return ports


def export_scan_json(target: str, result: str, ports: list[dict]) -> Path:
    payload = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "target": target,
        "ports": ports,
        "raw_output": result,
    }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", target)
    path = EXPORT_DIR / f"scan_{safe}_{ts}_{uuid4().hex[:8]}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    good(f"JSON export → {path}")
    return path


def _record_port_findings(scan_id: int, ports: list[dict]):
    for item in ports:
        meta = RISKY_PORTS.get(str(item["port"]))
        if not meta:
            continue
        service, level, note = meta
        severity = {"good": "info", "info": "info", "warn": "medium", "alert": "high"}[level]
        detail = f"{item['port']}/{item['protocol']} {service}: {note}"
        save_finding(scan_id, "open_port", severity, detail)
        if severity == "high":
            save_alert("scan", detail)


def run_scan(target: str = "localhost", no_confirm: bool = False, port_spec: Optional[str] = None):
    try:
        target = validate_target(target)
        if port_spec is not None:
            port_spec = validate_port_spec(port_spec)
    except ValueError as exc:
        alert(str(exc))
        return
    scope = f" ports {port_spec}" if port_spec else " default ports"
    if not no_confirm and not confirm(f"Run nmap -sV --open against '{target}' using{scope}? Only scan systems you own or are authorized to test."):
        info("Scan cancelled.")
        return
    title(f"NMAP SCAN → {target}")
    command = ["nmap", "-sV", "--open"]
    if port_spec:
        command.extend(["-p", port_spec])
    command.append(target)
    result, ok = run_command(command, timeout=180)
    print(result)
    ports = parse_nmap_ports(result)
    with db_connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans (timestamp, target, result, ports_json) VALUES (?,?,?,?)",
            (datetime.now().isoformat(timespec="seconds"), target, result, json.dumps(ports)),
        )
        scan_id = int(cur.lastrowid)
    _record_port_findings(scan_id, ports)
    export_scan_json(target, result, ports)
    if ok:
        good(f"Scan saved (id={scan_id}, open ports={len(ports)}).")
    else:
        warn(f"Nmap returned a non-zero status; output still saved as scan id={scan_id}.")


def show_services():
    title("ACTIVE SERVICES")
    out, _ = run_command(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"])
    print(out)


def show_processes():
    title("ACTIVE PROCESSES")
    out, _ = run_command(["ps", "aux", "--sort=-%cpu"])
    print("\n".join(out.splitlines()[:30]))


def show_authlog(lines: int = 80):
    title("AUTHENTICATION LOGS")
    authlog = Path("/var/log/auth.log")
    if authlog.exists():
        out, _ = run_command(["tail", "-n", str(lines), str(authlog)])
    else:
        out, _ = run_command(["journalctl", "-n", str(lines), "--no-pager"])
    print(out)


def show_firewall():
    title("FIREWALL STATUS")
    if shutil.which("ufw"):
        out, _ = run_command(["ufw", "status", "verbose"], require_root=True)
    elif shutil.which("nft"):
        out, _ = run_command(["nft", "list", "ruleset"], require_root=True)
    else:
        out = "[not found] Neither ufw nor nft is available."
    print(out)


def show_docker():
    title("DOCKER CONTAINER INSPECTION")
    if not shutil.which("docker"):
        alert("Docker is not installed.")
        return
    status, _ = run_command(["systemctl", "is-active", "docker"])
    (good if status.strip() == "active" else warn)(f"Docker service: {status.strip() or 'unknown'}")
    section("Running containers")
    out, _ = run_command(["docker", "ps"])
    print(out)


def show_users():
    title("USER AUDIT")
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        warn("/etc/passwd is unavailable.")
        return
    for line in passwd.read_text(errors="replace").splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, uid, shell = parts[0], parts[2], parts[6]
        try:
            uid_i = int(uid)
        except ValueError:
            continue
        if uid_i == 0 or uid_i >= 1000 or shell not in {"/usr/sbin/nologin", "/bin/false", "/usr/bin/false"}:
            print(f"{name:<20} {shell}")


def show_crons():
    title("CRON JOBS")
    out, _ = run_command(["crontab", "-l"])
    print(out.strip() or "(no user crontab output)")
    for path in (Path("/etc/crontab"),):
        if path.exists():
            section(str(path))
            print(path.read_text(errors="replace"))


def show_network():
    title("NETWORK INFORMATION")
    section("Interfaces")
    out, _ = run_command(["ip", "addr"])
    print(out)
    section("Routes")
    out, _ = run_command(["ip", "route"])
    print(out)
    section("Connections")
    out, _ = run_command(["ss", "-tunp"])
    print(out)


def show_findings(limit: int = 50):
    title("FINDINGS")
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, scan_id, category, severity, detail FROM findings ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    if not rows:
        dim("No findings recorded.")
        return
    for row in rows:
        print(f"{row['id']:>4} | {row['timestamp']} | {row['severity']:<6} | {row['category']:<12} | {row['detail']}")


def show_alerts(limit: int = 50):
    title("ALERTS")
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, source, message, resolved FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    if not rows:
        dim("No alerts recorded.")
        return
    for row in rows:
        state = "resolved" if row["resolved"] else "open"
        print(f"{row['id']:>4} | {row['timestamp']} | {state:<8} | {row['source']:<10} | {row['message']}")


def show_history(limit: int = 50):
    title("SCAN HISTORY")
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, target, ports_json FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    if not rows:
        dim("No scans recorded.")
        return
    for row in rows:
        try:
            count = len(json.loads(row["ports_json"] or "[]"))
        except (TypeError, json.JSONDecodeError):
            count = 0
        print(f"{row['id']:>4} | {row['timestamp']} | {row['target']:<30} | open={count}")


def generate_report():
    title("GENERATING REPORT")
    with db_connect() as conn:
        scan = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        if not scan:
            alert("No scan data available.")
            return
        findings = conn.execute(
            "SELECT severity, category, detail FROM findings WHERE scan_id=? ORDER BY id", (scan["id"],)
        ).fetchall()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"report_{ts}_{uuid4().hex[:8]}.txt"
    try:
        ports = json.loads(scan["ports_json"] or "[]")
    except (TypeError, json.JSONDecodeError):
        ports = []
    lines = [
        APP_NAME,
        f"Version: {APP_VERSION}",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"Scan ID: {scan['id']}",
        f"Target: {scan['target']}",
        f"Open ports parsed: {len(ports)}",
        "",
        "FINDINGS",
    ]
    lines.extend(f"- [{row['severity']}] {row['category']}: {row['detail']}" for row in findings)
    lines.extend(["", "RAW NMAP OUTPUT", scan["result"] or ""])
    path.write_text("\n".join(lines), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    good(f"Report saved → {path}")


def audit_local():
    """Read-only local audit that chains the primary observation commands."""
    title("LOCAL SECURITY AUDIT")
    show_status()
    show_ports()
    show_users()
    show_network()
    section("RECORDED FINDINGS")
    show_findings(limit=20)


def monitor(interval: int = 5):
    interval = max(1, interval)
    def _handler(_sig, _frame):
        print()
        good("Live monitor stopped.")
        raise SystemExit(0)
    signal.signal(signal.SIGINT, _handler)
    while True:
        os.system("clear")
        title(f"{APP_NAME} LIVE MONITOR")
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print(f"Machine: {platform.node()}")
        print(f"IP: {get_ip()}")
        section("Listening ports")
        out, _ = run_command(["ss", "-tulpn"])
        print("\n".join(out.splitlines()[:15]))
        warn(f"Refresh every {interval}s — CTRL+C to stop.")
        time.sleep(interval)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel", description=f"{APP_NAME} v{APP_VERSION}")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-y", "--yes", action="store_true", help="skip scan confirmation")
    sub = parser.add_subparsers(dest="command")
    for cmd in ("status", "ports", "services", "processes", "authlog", "firewall", "docker", "users", "crons", "network", "findings", "alerts", "history", "report", "audit"):
        sub.add_parser(cmd)
    monitor_p = sub.add_parser("monitor")
    monitor_p.add_argument("--interval", type=int, default=5)
    scan_p = sub.add_parser("scan")
    scan_p.add_argument("target", nargs="?", default="localhost")
    scan_p.add_argument("--ports", help="comma-separated ports or ranges, for example 22,80,443,8000-8100")
    return parser


def main():
    global logger
    parser = build_parser()
    args = parser.parse_args()
    logger = setup_logging(verbose=args.verbose)
    init_db()
    commands = {
        "status": show_status,
        "ports": show_ports,
        "services": show_services,
        "processes": show_processes,
        "authlog": show_authlog,
        "firewall": show_firewall,
        "docker": show_docker,
        "users": show_users,
        "crons": show_crons,
        "network": show_network,
        "findings": show_findings,
        "alerts": show_alerts,
        "history": show_history,
        "report": generate_report,
        "audit": audit_local,
    }
    if args.command == "scan":
        run_scan(args.target, no_confirm=args.yes, port_spec=args.ports)
    elif args.command == "monitor":
        monitor(args.interval)
    elif args.command in commands:
        commands[args.command]()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
