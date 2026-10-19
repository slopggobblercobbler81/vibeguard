"""Unit tests for the data models.

These cover the properties and serialisation methods that the formatters
and CLI rely on but that were only exercised indirectly through them.
"""

from vibeguard.models import (
    SKIP_PATTERNS,
    SUPPORTED_EXTENSIONS,
    Finding,
    ScanResult,
    Severity,
)

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


def test_severity_values():
    assert Severity.CRITICAL == "CRITICAL"
    assert Severity.HIGH == "HIGH"
    assert Severity.MEDIUM == "MEDIUM"
    assert Severity.LOW == "LOW"


# ---------------------------------------------------------------------------
# Finding.to_dict
# ---------------------------------------------------------------------------


def test_finding_to_dict_full():
    f = Finding(
        rule_id="VGB-001",
        severity=Severity.HIGH,
        message="hardcoded secret",
        file="app.py",
        line=10,
        column=5,
        snippet="API_KEY = 'REDACTEDFAKEKEYDONTUSE0000'",
        fix_hint="Use an environment variable",
    )
    d = f.to_dict()
    assert d == {
        "rule_id": "VGB-001",
        "severity": "HIGH",
        "message": "hardcoded secret",
        "file": "app.py",
        "line": 10,
        "column": 5,
        "snippet": "API_KEY = 'REDACTEDFAKEKEYDONTUSE0000'",
        "fix_hint": "Use an environment variable",
    }


def test_finding_to_dict_defaults():
    f = Finding(rule_id="VGB-002", severity=Severity.LOW, message="m", file="f.py")
    d = f.to_dict()
    assert d["line"] == 0
    assert d["column"] == 0
    assert d["snippet"] == ""
    assert d["fix_hint"] == ""


# ---------------------------------------------------------------------------
# ScanResult properties
# ---------------------------------------------------------------------------


def test_scan_result_empty():
    r = ScanResult(target="target", files_scanned=0, lines_scanned=0)
    assert not r.has_findings
    assert r.critical_count == 0
    assert r.high_count == 0
    assert r.by_severity() == {}


def test_scan_result_has_findings():
    r = ScanResult(
        target="target",
        findings=[Finding("VGB-001", Severity.CRITICAL, "m", "f.py")],
    )
    assert r.has_findings


def test_scan_result_critical_count():
    r = ScanResult(
        target="target",
        findings=[
            Finding("VGB-001", Severity.CRITICAL, "m", "f.py"),
            Finding("VGB-002", Severity.CRITICAL, "m", "f.py"),
            Finding("VGB-003", Severity.HIGH, "m", "f.py"),
        ],
    )
    assert r.critical_count == 2
    assert r.high_count == 1


def test_scan_result_by_severity_groups():
    r = ScanResult(
        target="target",
        findings=[
            Finding("VGB-001", Severity.CRITICAL, "m", "a.py"),
            Finding("VGB-002", Severity.HIGH, "m", "b.py"),
            Finding("VGB-003", Severity.HIGH, "m", "c.py"),
            Finding("VGB-004", Severity.LOW, "m", "d.py"),
        ],
    )
    groups = r.by_severity()
    assert len(groups["CRITICAL"]) == 1
    assert len(groups["HIGH"]) == 2
    assert len(groups["LOW"]) == 1
    assert groups["CRITICAL"][0].rule_id == "VGB-001"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_supported_extensions_include_languages():
    for ext in (".py", ".js", ".go", ".rs", ".java", ".rb"):
        assert ext in SUPPORTED_EXTENSIONS


def test_skip_patterns_include_common_dirs():
    for pat in ("node_modules", ".git", "__pycache__", "venv"):
        assert pat in SKIP_PATTERNS
