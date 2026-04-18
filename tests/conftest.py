# tests/conftest.py
"""Pytest configuration and shared fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def examples_dir() -> Path:
    return Path(__file__).parent.parent / "examples" / "vulnerable_apps"


@pytest.fixture
def python_file(tmp_path: Path) -> Path:
    return tmp_path / "test_app.py"


@pytest.fixture
def ts_file(tmp_path: Path) -> Path:
    return tmp_path / "test_app.ts"
