"""
BLACKFONG SENTINEL - Upgraded Security Monitoring Tool
"""

import os
import platform
import sqlite3
import subprocess
import sys
import json
import time
import logging
import re
import shutil
import signal
import argparse
from datetime import datetime
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

APP_NAME    = "BLACKFONG SENTINEL"
APP_VERSION = "2.0.0"

BASE_DIR   = Path(__file__).parent
DATA_DIR   = BASE_DIR / "data"
REPORT_DIR = BASE_DIR / "reports"
EXPORT_DIR = BASE_DIR / "exports"
LOG_DIR    = BASE_DIR / "logs"
DB_PATH    = DATA_DIR / "sentinel.db"

for _dir in [DATA_DIR, REPORT_DIR, EXPORT_DIR, LOG_DIR]:
    _dir.mkdir(exist_ok=True)

IS_ROOT = os.geteuid() == 0


# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────

def setup_logging(verbose: bool = False) -> logging.Logger:
    log_file = LOG_DIR / f"sentinel_{datetime.now().strftime('%Y%m%d')}.log"
    level    = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),
        ],
    )
    return logging.getLogger("sentinel")


logger = logging.getLogger("sentinel")


# ─────────────────────────────────────────────
# COLOR OUTPUT
# ─────────────────────────────────────────────

class Color:
    RESET  = "\033[0m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"


def _c(color: str, text: str) -> str:
    return f"{color}{text}{Color.RESET}"


def info(text):  print(_c(Color.BLUE,   f"[~] {text}"))
def good(text):  print(_c(Color.GREEN,  f"[+] {text}"))
def warn(text):  print(_c(Color.YELLOW, f"[!] {text}"))
def alert(text): print(_c(Color.RED,    f"[X] {text}"))
def dim(text):   print(_c(Color.DIM,    f"    {text}"))


def title(text: str):
    width  = 60
    border = "─" * width
    print(f"\n{Color.BOLD}{Color.CYAN}┌{border}┐")
    print(f"│  {text:<{width - 2}}│")
    print(f"└{border}┘{Color.RESET}\n")


def section(text: str):
    print(f"\n{Color.BOLD}{Color.BLUE}── {text} ──{Color.RESET}\n")


def confirm(prompt: str) -> bool:
    answer = input(f"{Color.YELLOW}[?] {prompt} [y/N]: {Color.RESET}").strip().lower()
    return answer in ("y", "yes")


# ─────────────────────────────────────────────
# COMMAND RUNNER
# ─────────────────────────────────────────────

def run_command(
    command: list[str],
    timeout: int = 30,
    require_root: bool = False,
) -> tuple[str, bool]:

    if require_root and not IS_ROOT:
        warn(f"Command '{command[0]}' may need root privileges. Results may be incomplete.")

    binary = command[0]
    if not shutil.which(binary):
        return f"[not found] '{binary}' is not installed or not in PATH.", False

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        output = result.stdout or result.stderr or ""
        return output, result.returncode == 0

    except subprocess.TimeoutExpired:
        logger.warning("Command timed out: %s", " ".join(command))
        return f"[timeout] Command exceeded {timeout}s.", False

    except Exception as e:
        logger.error("Command failed: %s — %s", " ".join(command), e)
        return f"[error] {e}", False


# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT    NOT NULL,
    target     TEXT    NOT NULL,
    result     TEXT,
    ports_json TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER REFERENCES scans(id),
    timestamp  TEXT    NOT NULL,
    category   TEXT    NOT NULL,
    severity   TEXT    NOT NULL,
    detail     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT    NOT NULL,
    source     TEXT    NOT NULL,
    message    TEXT    NOT NULL,
    resolved   INTEGER DEFAULT 0
);
"""


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(DB_SCHEMA)
    logger.debug("Database initialised at %s", DB_PATH)


def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def save_finding(
    scan_id: Optional[int],
    category: str,
    severity: str,
    detail: str,
):
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO findings (scan_id, timestamp, category, severity, detail) VALUES (?,?,?,?,?)",
            (scan_id, datetime.now().isoformat(), category, severity, detail),
        )


def save_alert(source: str, message: str):
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO alerts (timestamp, source, message) VALUES (?,?,?)",
            (datetime.now().isoformat(), source, message),
        )
    alert(f"ALERT — {source}: {message}")
    logger.warning("ALERT [%s]: %s", source, message)


# ─────────────────────────────────────────────
# INPUT VALIDATION
# ─────────────────────────────────────────────

_TARGET_RE = re.compile(
    r"^("
    r"localhost"
    r"|(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?"
    r"|[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
    r")$"
)


def validate_target(target: str) -> str:
    target = target.strip()
    if not _TARGET_RE.match(target):
        raise ValueError(
            f"Invalid target '{target}'. "
            "Allowed: localhost, IPv4, IPv4 CIDR, or hostname."
        )
    return target


def get_ip() -> str:
    out, _ = run_command(["hostname", "-I"])
    return out.strip() or "Unknown"


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
    "21":   ("FTP",           "warn",  "Cleartext file transfer — prefer SFTP."),
    "22":   ("SSH",           "info",  "Remote terminal — ensure key-based auth only."),
    "23":   ("Telnet",        "alert", "Cleartext terminal — disable immediately."),
    "80":   ("HTTP",          "warn",  "Unencrypted web traffic."),
    "443":  ("HTTPS",         "good",  "Encrypted web traffic."),
    "445":  ("SMB",           "alert", "Windows file sharing exposure."),
    "3389": ("RDP/XRDP",      "warn",  "Remote desktop — brute-force target."),
    "8080": ("HTTP-alt",      "warn",  "Dev/proxy web service."),
}


def show_ports():
    title("OPEN LISTENING PORTS")

    out, ok = run_command(["ss", "-tulpn"], require_root=True)
    if not ok:
        warn("Could not retrieve port information.")

    print(out)

    section("SENTINEL INTERPRETATION")

    for port, (service, level, note) in RISKY_PORTS.items():
        if f":{port}" in out or f":{port} " in out:
            fn = {"info": info, "good": good, "warn": warn, "alert": alert}[level]
            fn(f"[:{port}] {service} — {note}")


def parse_nmap_ports(nmap_output: str) -> list[dict]:
    ports = []
    for line in nmap_output.splitlines():
        if "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                port_proto = parts[0]
                port_num, proto = port_proto.split("/")
                ports.append({
                    "port":     port_num,
                    "protocol": proto,
                    "state":    parts[1],
                    "service":  parts[2],
                    "version":  " ".join(parts[3:]),
                })
    return ports


def export_scan_json(target: str, result: str, ports: list[dict]) -> Path:
    data = {
        "app":        APP_NAME,
        "version":    APP_VERSION,
        "timestamp":  datetime.now().isoformat(),
        "target":     target,
        "ports":      ports,
        "raw_output": result,
    }

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe     = target.replace(".", "_").replace("/", "_")
    out_path = EXPORT_DIR / f"scan_{safe}_{ts}.json"

    with open(out_path, "w") as f:
        json.dump(data, f, indent=4)

    good(f"JSON export → {out_path}")
    return out_path


def run_scan(target: str = "localhost", no_confirm: bool = False):
    try:
        target = validate_target(target)
    except ValueError as e:
        alert(str(e))
        return

    if not no_confirm:
        if not confirm(f"Run nmap -sV scan against '{target}'?"):
            info("Scan cancelled.")
            return

    title(f"NMAP SERVICE SCAN → {target}")

    result, ok = run_command(["nmap", "-sV", "--open", target], timeout=120)
    print(result)

    ports = parse_nmap_ports(result)

    with db_connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans (timestamp, target, result, ports_json) VALUES (?,?,?,?)",
            (datetime.now().isoformat(), target, result, json.dumps(ports)),
        )
        scan_id = cur.lastrowid

    good(f"Scan saved (id={scan_id}).")

    export_scan_json(target, result, ports)


def show_services():
    title("ACTIVE SERVICES")

    out, _ = run_command([
        "systemctl", "list-units",
        "--type=service", "--state=running", "--no-pager",
    ])

    print(out)


def show_processes():
    title("ACTIVE PROCESSES")

    out, _ = run_command(["ps", "aux", "--sort=-%cpu"])
    lines = out.splitlines()

    for line in lines[:30]:
        print(line)


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

    ufw_out, ufw_ok = run_command(["ufw", "status", "verbose"])

    if ufw_ok:
        print(ufw_out)
    else:
        warn("UFW unavailable.")


def show_docker():
    title("DOCKER CONTAINER INSPECTION")

    if not shutil.which("docker"):
        alert("Docker is not installed.")
        return

    status_out, _ = run_command(["systemctl", "is-active", "docker"])

    if status_out.strip() == "active":
        good("Docker service: active")
    else:
        warn(f"Docker service: {status_out.strip()}")

    section("Running containers")
    ps_out, _ = run_command(["docker", "ps"])
    print(ps_out)


# ─────────────────────────────────────────────
# LIVE MONITOR
# ─────────────────────────────────────────────

def monitor(interval: int = 5):
    def _handler(sig, frame):
        print()
        good("Live monitor stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, _handler)

    while True:
        os.system("clear")
        title(f"{APP_NAME} LIVE MONITOR")

        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Machine: {platform.node()}")
        print(f"IP: {get_ip()}")

        section("Listening ports")
        ports_out, _ = run_command(["ss", "-tulpn"])
        for line in ports_out.splitlines()[:12]:
            print(line)

        print()
        warn(f"Refresh every {interval}s — CTRL+C to stop.")

        time.sleep(interval)


def show_history():
    title("SCAN HISTORY")

    with db_connect() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, target FROM scans ORDER BY id DESC"
        ).fetchall()

    for row in rows:
        print(f"{row['id']} | {row['timestamp']} | {row['target']}")


def generate_report():
    title("GENERATING REPORT")

    with db_connect() as conn:
        scan = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()

    if not scan:
        alert("No scan data available.")
        return

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_path = REPORT_DIR / f"report_{ts}.txt"

    with open(txt_path, "w") as f:
        f.write(scan["result"])

    good(f"Report saved → {txt_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description=f"{APP_NAME} v{APP_VERSION}",
    )

    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-y", "--yes", action="store_true")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status")
    sub.add_parser("ports")
    sub.add_parser("services")
    sub.add_parser("processes")
    sub.add_parser("authlog")
    sub.add_parser("firewall")
    sub.add_parser("docker")
    sub.add_parser("history")
    sub.add_parser("report")

    monitor_p = sub.add_parser("monitor")
    monitor_p.add_argument("--interval", type=int, default=5)

    scan_p = sub.add_parser("scan")
    scan_p.add_argument("target", nargs="?", default="localhost")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(verbose=args.verbose)
    init_db()

    cmd = args.command

    if cmd == "status":
        show_status()
    elif cmd == "ports":
        show_ports()
    elif cmd == "services":
        show_services()
    elif cmd == "processes":
        show_processes()
    elif cmd == "authlog":
        show_authlog()
    elif cmd == "firewall":
        show_firewall()
    elif cmd == "docker":
        show_docker()
    elif cmd == "scan":
        run_scan(target=args.target, no_confirm=args.yes)
    elif cmd == "monitor":
        monitor(interval=args.interval)
    elif cmd == "history":
        show_history()
    elif cmd == "report":
        generate_report()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
