"""Process runner for the advanced headless browser URL sandbox."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from shared.schemas import BrowserSandboxURLResponse


def _browser_worker_environment() -> dict[str, str]:
    """Return the minimal environment needed by the isolated browser worker."""
    worker_env = {"PYTHONIOENCODING": "utf-8"}
    keep_env = (
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "LOCALAPPDATA",
        "APPDATA",
        "USERPROFILE",
        "TEMP",
        "TMP",
        "LANG",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "BRAND_VISUAL_HASH_REGISTRY",
        # Production installs Chromium into a shared, non-root-readable path.
        # The worker receives a deliberately reduced environment, so this must
        # be forwarded explicitly instead of falling back to ~/.cache.
        "PLAYWRIGHT_BROWSERS_PATH",
    )
    for name in keep_env:
        if value := os.environ.get(name):
            worker_env[name] = value
    return worker_env


class BrowserSandboxRunner:
    def __init__(
        self,
        process_timeout_seconds: float = 35.0,
        navigation_timeout_ms: int = 15_000,
    ) -> None:
        self.process_timeout_seconds = process_timeout_seconds
        self.navigation_timeout_ms = navigation_timeout_ms
        self.worker_path = Path(__file__).with_name("browser_sandbox_worker.py")

    def inspect(self, url: str, canary_mode: str = "dry_run") -> BrowserSandboxURLResponse:
        payload = json.dumps(
            {
                "url": url,
                "canary_mode": canary_mode,
                "timeout_ms": self.navigation_timeout_ms,
            },
            ensure_ascii=False,
        )
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        worker_env = _browser_worker_environment()

        # Browser descendants can retain inherited stdout/stderr handles on Windows
        # after the worker has already completed. A pipe-based JSON protocol then
        # waits forever for EOF and incorrectly reports a sandbox timeout. Return the
        # result through a private temporary file and keep browser stdio on DEVNULL so
        # process completion, not descendant pipe lifetime, controls the timeout.
        result_file = tempfile.NamedTemporaryFile(
            prefix="aisec-browser-result-",
            suffix=".json",
            delete=False,
        )
        result_path = Path(result_file.name)
        result_file.close()
        progress_file = tempfile.NamedTemporaryFile(
            prefix="aisec-browser-progress-",
            suffix=".txt",
            delete=False,
        )
        progress_path = Path(progress_file.name)
        progress_file.close()
        try:
            worker_env["AISEC_BROWSER_RESULT_PATH"] = str(result_path)
            worker_env["AISEC_BROWSER_PROGRESS_PATH"] = str(progress_path)
            process = subprocess.Popen(
                [sys.executable, "-I", str(self.worker_path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                cwd=str(self.worker_path.parent),
                env=worker_env,
                creationflags=creationflags,
                start_new_session=os.name != "nt",
            )
            try:
                if process.stdin is None:
                    raise BrokenPipeError("Browser worker stdin was not created")
                process.stdin.write(payload)
                process.stdin.close()
                process.stdin = None
            except (BrokenPipeError, OSError) as exc:
                self._terminate_process_tree(process)
                return BrowserSandboxURLResponse.failed(
                    url,
                    "browser_sandbox_process_error",
                    "Browser sandbox process exited unexpectedly.",
                    str(exc),
                )

            deadline = time.monotonic() + self.process_timeout_seconds
            while time.monotonic() < deadline:
                completed = self._read_result(result_path)
                if completed is not None:
                    # The process boundary is also the cleanup boundary. Once the
                    # validated result has been written, terminate any browser tree
                    # still blocked while closing its persistent context.
                    self._terminate_process_tree(process)
                    return completed
                if process.poll() is not None:
                    break
                time.sleep(0.05)

            if process.poll() is None:
                self._terminate_process_tree(process)
                try:
                    last_stage = progress_path.read_text(encoding="utf-8").strip()
                except OSError:
                    last_stage = ""
                return BrowserSandboxURLResponse.failed(
                    url,
                    "browser_sandbox_timeout",
                    "Browser sandbox stopped the process because it exceeded the time limit.",
                    (
                        f"Limit {self.process_timeout_seconds:g} seconds"
                        + (f"; last stage: {last_stage}" if last_stage else "")
                    ),
                )

            if process.returncode != 0:
                return BrowserSandboxURLResponse.failed(
                    url,
                    "browser_sandbox_process_error",
                    "Browser sandbox process exited unexpectedly.",
                    f"Exit code {process.returncode}",
                )
            return BrowserSandboxURLResponse.failed(
                url,
                "browser_sandbox_invalid_output",
                "Browser sandbox returned invalid data.",
                "Worker exited without a complete result file.",
            )
        finally:
            for path in (result_path, progress_path):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    # A browser descendant can briefly retain a Windows handle. The
                    # OS temporary-file cleanup policy can safely collect this file.
                    pass

    @staticmethod
    def _read_result(path: Path) -> BrowserSandboxURLResponse | None:
        try:
            output = path.read_text(encoding="utf-8")
            if not output.strip():
                return None
            return BrowserSandboxURLResponse.model_validate_json(output)
        except (OSError, ValueError):
            # The worker can be between truncate/write operations. Retry until it
            # exits or the outer process deadline is reached.
            return None

    @staticmethod
    def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
        """Close browser descendants so inherited pipes cannot outlive the timeout."""
        if process.poll() is not None:
            return
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                check=False,
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
