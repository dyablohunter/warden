"""Small helpers: subprocess runner, truncation, time formatting."""
from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass

SAFE_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C.UTF-8",
    "LANG": "C.UTF-8",
    "TERM": "dumb",
    "SYSTEMD_PAGER": "",
    "PAGER": "cat",
    "DEBIAN_FRONTEND": "noninteractive",
    "HOME": "/root",
}


@dataclass
class CmdResult:
    code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration: float = 0.0

    @property
    def ok(self) -> bool:
        return self.code == 0 and not self.timed_out

    def render(self, limit: int = 8000) -> str:
        parts = [f"exit={self.code}" + (" (TIMED OUT)" if self.timed_out else "") + f" duration={self.duration:.1f}s"]
        if self.stdout.strip():
            parts.append("--- stdout ---\n" + truncate(self.stdout, int(limit * 0.8)))
        if self.stderr.strip():
            parts.append("--- stderr ---\n" + truncate(self.stderr, int(limit * 0.2)))
        return "\n".join(parts)


def run(cmd: str | list[str], timeout: float = 60, input_text: str | None = None) -> CmdResult:
    """Run a command (string -> bash -c) with a hard timeout that kills the whole process group."""
    argv = ["/bin/bash", "-o", "pipefail", "-c", cmd] if isinstance(cmd, str) else cmd
    env = dict(SAFE_ENV)
    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
    except OSError as exc:
        return CmdResult(127, "", str(exc), duration=time.monotonic() - start)
    try:
        out, err = proc.communicate(input=input_text.encode() if input_text is not None else None, timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, AttributeError):
            proc.kill()
        out, err = proc.communicate()
    return CmdResult(
        code=proc.returncode if proc.returncode is not None else -1,
        stdout=out.decode("utf-8", "replace"),
        stderr=err.decode("utf-8", "replace"),
        timed_out=timed_out,
        duration=time.monotonic() - start,
    )


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    head = int(limit * 0.6)
    tail = limit - head
    omitted = len(text) - head - tail
    return f"{text[:head]}\n... [{omitted} chars omitted] ...\n{text[-tail:]}"


def now() -> float:
    return time.time()


def iso(ts: float | None) -> str:
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def ago(ts: float | None) -> str:
    if not ts:
        return "never"
    d = int(time.time() - ts)
    sign = "" if d >= 0 else "in "
    d = abs(d)
    if d < 60:
        s = f"{d}s"
    elif d < 3600:
        s = f"{d // 60}m"
    elif d < 86400:
        s = f"{d // 3600}h{(d % 3600) // 60:02d}m"
    else:
        s = f"{d // 86400}d{(d % 86400) // 3600}h"
    return f"{sign}{s}" + (" ago" if not sign else "")
