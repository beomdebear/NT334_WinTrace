"""Run Plaso commands reproducibly and persist execution diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
from typing import Dict, List, Optional, Sequence


class PlasoCommandError(RuntimeError):
    """Raised when a Plaso command cannot be started or exits unsuccessfully."""


@dataclass(frozen=True)
class PlasoRunResult:
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    started_at: str
    finished_at: str


class PlasoRunner:
    """Small subprocess wrapper for log2timeline, pinfo, and psort."""

    def __init__(self, executable: str = "log2timeline.py", psort_executable: str = "psort.py"):
        self.executable = executable
        self.psort_executable = psort_executable

    def _run(
        self,
        command: Sequence[str],
        log_path: Optional[str] = None,
        cwd: Optional[str] = None,
    ) -> PlasoRunResult:
        started = datetime.now(timezone.utc)
        try:
            completed = subprocess.run(
                list(command),
                cwd=cwd,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            raise PlasoCommandError(
                f"Unable to start Plaso command {list(command)!r}: {exc}"
            ) from exc
        finished = datetime.now(timezone.utc)
        result = PlasoRunResult(
            command=list(command),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
        )
        self._write_log(result, log_path)
        if result.returncode != 0:
            raise PlasoCommandError(
                f"Plaso command exited with code {result.returncode}: "
                f"{completed.stderr.strip() or completed.stdout.strip()}"
            )
        return result

    @staticmethod
    def _write_log(result: PlasoRunResult, log_path: Optional[str]) -> None:
        if not log_path:
            return
        path = Path(log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "command": result.command,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "started_at": result.started_at,
                "finished_at": result.finished_at,
            }, ensure_ascii=False) + "\n")

    def run_log2timeline(
        self,
        source: str,
        storage_file: str,
        parsers: Optional[str] = None,
        log_path: Optional[str] = None,
        extra_args: Optional[Sequence[str]] = None,
    ) -> PlasoRunResult:
        command = [
            self.executable,
            "--status_view", "none",
            "--storage_file", storage_file,
        ]
        if parsers:
            command.extend(["--parsers", parsers])
        if extra_args:
            command.extend(extra_args)
        command.append(source)
        return self._run(command, log_path)

    def run_psort(
        self,
        storage_file: str,
        output_file: str,
        output_format: str = "dynamic",
        log_path: Optional[str] = None,
        extra_args: Optional[Sequence[str]] = None,
    ) -> PlasoRunResult:
        command = [
            self.psort_executable,
            "-o", output_format,
            "-w", output_file,
        ]
        if extra_args:
            command.extend(extra_args)
        command.append(storage_file)
        return self._run(command, log_path)
