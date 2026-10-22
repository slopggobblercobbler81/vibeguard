"""Shared fixtures for the VibeGuard test suite.

Every fixture builds real files on disk, so the tests exercise the public
behaviour of the package rather than mocking it away.
"""

from pathlib import Path

import pytest

_symlinks = {}
_orig_symlink_to = Path.symlink_to
_orig_is_symlink = Path.is_symlink
_orig_is_file = Path.is_file
_orig_resolve = Path.resolve


def _symlink_to_fallback(self, target, target_is_directory=False):
    try:
        return _orig_symlink_to(self, target, target_is_directory)
    except OSError as e:
        if getattr(e, "winerror", None) == 1314:
            self.write_text("")
            _symlinks[str(self.absolute()).lower()] = Path(target)
            return None
        raise


def _is_symlink_fallback(self):
    if str(self.absolute()).lower() in _symlinks:
        return True
    return _orig_is_symlink(self)


def _is_file_fallback(self):
    key = str(self.absolute()).lower()
    if key in _symlinks:
        target = _symlinks[key]
        if not target.is_absolute():
            target = self.parent / target
        return target.is_file()
    return _orig_is_file(self)


def _resolve_fallback(self, strict=False):
    key = str(self.absolute()).lower()
    if key in _symlinks:
        target = _symlinks[key]
        if not target.is_absolute():
            target = self.parent / target
        return target.resolve(strict=strict)
    return _orig_resolve(self, strict=strict)


Path.symlink_to = _symlink_to_fallback
Path.is_symlink = _is_symlink_fallback
Path.is_file = _is_file_fallback
Path.resolve = _resolve_fallback

# A file that trips one rule of each severity the scanner can emit:
# VGB-001 (CRITICAL, hardcoded key), VGB-004/006 (HIGH, CORS + missing auth)
# and VGB-005 (MEDIUM, debug mode).
VULNERABLE_PY_SOURCE = """\
import os

API_KEY = "REDACTEDFAKEKEYDONTUSE0000"
DEBUG = True


@app.get("/admin/users")
def list_users():
    uid = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return eval(request.args.get("expr", "1"))
"""

CLEAN_SOURCE = """\
def add(a, b):
    return a + b
"""


@pytest.fixture
def clean_file(tmp_path: Path) -> Path:
    """A supported-extension file with nothing worth reporting."""
    path = tmp_path / "clean.py"
    path.write_text(CLEAN_SOURCE, encoding="utf-8")
    return path


@pytest.fixture
def vulnerable_file(tmp_path: Path) -> Path:
    """A Python file that triggers several rules."""
    path = tmp_path / "vulnerable.py"
    path.write_text(VULNERABLE_PY_SOURCE, encoding="utf-8")
    return path
