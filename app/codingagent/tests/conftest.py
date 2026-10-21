import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from coding.config import Settings, configure  # noqa: E402


@pytest.fixture
def ws(tmp_path, monkeypatch):
    """An isolated workspace with no git identity, so tests never touch the real environment."""
    root = tmp_path / "ws"
    root.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("EXTRA_READ_TOOLS", raising=False)
    configure(Settings(workspace=root.resolve()))
    return root.resolve()
