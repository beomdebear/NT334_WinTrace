import json

import pytest

from src.plaso_runner import PlasoCommandError, PlasoRunner


def test_runner_writes_execution_log(tmp_path):
    log_path = tmp_path / "run.jsonl"
    runner = PlasoRunner(executable="python", psort_executable="python")
    result = runner._run(["python", "-c", "print('ok')"], str(log_path))

    assert result.returncode == 0
    record = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert record["returncode"] == 0
    assert "ok" in record["stdout"]


def test_runner_surfaces_command_failure(tmp_path):
    runner = PlasoRunner(executable="python")
    with pytest.raises(PlasoCommandError, match="exited with code"):
        runner._run(["python", "-c", "raise SystemExit(3)"], str(tmp_path / "run.jsonl"))
