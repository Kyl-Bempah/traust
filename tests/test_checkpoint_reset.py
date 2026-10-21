"""`checkpoint reset` leaves an empty state directory, not a missing one.

Skills write into their state dir before the first `save` (the threat-model
bootstrap's checkov seed, for one), so a reset that only deleted the dir
made that first write fail.
"""

import pytest

from traust.cli import checkpoint


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setattr(checkpoint, "_ROOT", tmp_path.resolve())
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_reset_creates_a_missing_state_dir(root):
    assert checkpoint.cmd_reset([".threat-model-state"]) == 0
    state = root / ".threat-model-state"
    assert state.is_dir() and list(state.iterdir()) == []


def test_reset_empties_an_existing_state_dir(root):
    state = root / ".triage-state"
    (state / "nested").mkdir(parents=True)
    (state / "progress.json").write_text("{}")
    assert checkpoint.cmd_reset([".triage-state"]) == 0
    assert state.is_dir() and list(state.iterdir()) == []


def test_reset_still_refuses_a_dir_that_is_not_a_state_dir(root):
    (root / "src").mkdir()
    with pytest.raises(SystemExit):
        checkpoint.cmd_reset(["src"])
    assert (root / "src").is_dir()
