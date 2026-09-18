import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sentinel", ROOT / "sentinel.py")
sentinel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sentinel)


def test_parse_nmap_ports():
    sample = """PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2
8080/tcp open  http    Werkzeug
"""
    ports = sentinel.parse_nmap_ports(sample)
    assert [p["port"] for p in ports] == ["22", "8080"]
    assert ports[0]["service"] == "ssh"


def test_validate_target():
    assert sentinel.validate_target("localhost") == "localhost"
    assert sentinel.validate_target("127.0.0.1") == "127.0.0.1"
    assert sentinel.validate_target("192.168.1.0/24") == "192.168.1.0/24"


def test_validate_target_rejects_shell_input():
    for target in ("127.0.0.1;id", "$(whoami)", "host name"):
        try:
            sentinel.validate_target(target)
        except ValueError:
            continue
        raise AssertionError(f"accepted unsafe target: {target}")


def test_validate_port_spec():
    assert sentinel.validate_port_spec("22,80,443,8000-8100") == "22,80,443,8000-8100"
    for port_spec in ("0", "65536", "80-22", "22;id", ""):
        try:
            sentinel.validate_port_spec(port_spec)
        except ValueError:
            continue
        raise AssertionError(f"accepted invalid port specification: {port_spec}")


def test_export_scan_json_uses_unique_names(tmp_path, monkeypatch):
    monkeypatch.setattr(sentinel, "EXPORT_DIR", tmp_path)
    first = sentinel.export_scan_json("localhost", "", [])
    second = sentinel.export_scan_json("localhost", "", [])
    assert first != second
    assert first.exists()
    assert second.exists()
