# BLACKFONG SENTINEL — Recovered Project

Recovered from the original Sentinel v2 source and terminal captures from the prior build.

## What Sentinel is

A Kali/Linux-first, local security monitoring and lab CLI for observing your own machine and intentionally authorized targets. It stores scan history in SQLite, exports Nmap scan results, generates reports, and exposes local inspection commands.

## Restored commands

```bash
python3 sentinel.py status
python3 sentinel.py ports
python3 sentinel.py services
python3 sentinel.py processes
python3 sentinel.py authlog
python3 sentinel.py firewall
python3 sentinel.py docker
python3 sentinel.py users
python3 sentinel.py crons
python3 sentinel.py network
python3 sentinel.py findings
python3 sentinel.py alerts
python3 sentinel.py history
python3 sentinel.py report
python3 sentinel.py monitor --interval 5
python3 sentinel.py scan localhost
python3 sentinel.py scan localhost --ports 22,80,443,8000-8100
python3 sentinel.py -y scan localhost
python3 sentinel.py audit
```

## Recovery notes

The `archive/` folder contains the exact recovered v2 source paste and the later runtime capture. The active `sentinel.py` is a reconstructed/hardened recovery that restores later commands demonstrated in the runtime capture.

The last historical build failed because an older SQLite database already had a `scans` table without the later `ports_json` column. This recovery includes an in-place migration check so an older Sentinel database can be upgraded instead of crashing.

## Kali prerequisites

Python uses only the standard library. Sentinel can make use of these system tools when installed:

- `nmap`
- `ip` / `iproute2`
- `ss`
- `systemctl`
- `journalctl`
- `ufw` or `nft`
- Docker (optional)

On Kali, the core tools can be checked with:

```bash
command -v python3 nmap ip ss systemctl journalctl
```

## First run

```bash
cd BLACKFONG-Sentinel-Recovered
chmod +x sentinel.py
python3 sentinel.py status
python3 sentinel.py ports
python3 sentinel.py -y scan localhost
python3 sentinel.py findings
python3 sentinel.py report
```

Use network scanning only against systems you own or are authorized to test.
The optional `--ports` argument limits an authorized scan to explicit ports or ranges; omitting it preserves Nmap's default port selection.

## Running the tests

The suite runs under `pytest` — the tests use its `tmp_path` and `monkeypatch`
fixtures, so it is the supported runner. Install the development dependency once,
then run it from the project root:

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest
```

`pytest.ini` points at `tests/`, so a bare `python3 -m pytest` collects the whole
suite with no arguments. To run one test:

```bash
python3 -m pytest tests/test_sentinel.py::test_validate_port_spec
```

`pytest` is required only for the tests. Running `sentinel.py` itself still needs
nothing beyond the Python standard library.

## Project layout

```text
BLACKFONG-Sentinel-Recovered/
├── sentinel.py
├── README.md
├── requirements.txt
├── requirements-dev.txt
├── pytest.ini
├── data/
├── reports/
├── exports/
├── logs/
├── docs/
│   └── Blackfong_Sentinel_Training_Guide.pdf
├── tests/
│   └── test_sentinel.py
└── archive/
    ├── sentinel_v2_original.py
    ├── sentinel_v2_original_paste.txt
    └── sentinel_v2_runtime_capture.txt
```
