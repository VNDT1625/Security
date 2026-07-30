from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SOURCE = ROOT / "tests" / "fixtures" / "sandbox" / "native_phishing_simulator.go"
FIXTURE_MANIFEST = ROOT / "tests" / "fixtures" / "sandbox" / "native_phishing_simulator.json"
AGENT_SOURCE = ROOT / "server" / "sandbox-agent" / "PrewiseSandboxAgent.ps1"


def test_native_fixture_is_harmless_and_matches_agent_scoring_contract() -> None:
    source = FIXTURE_SOURCE.read_text(encoding="utf-8")
    manifest = json.loads(FIXTURE_MANIFEST.read_text(encoding="utf-8"))
    agent = AGENT_SOURCE.read_text(encoding="utf-8")

    assert '"net"' not in source
    assert '"net/http"' not in source
    assert "no credential collection" in source
    assert "TRAINING_ONLY" in source
    assert "PREWISE_PHISHING_SIMULATION_ONLY" in source
    assert "RegSetValueExW" in source
    assert "CurrentVersion\\Run" in source
    assert 'exec.Command("cmd.exe"' in source

    weights = {
        signal: int(weight)
        for signal, weight in re.findall(
            r"Add-RiskSignal\s+'([A-Z0-9_]+)'\s+(\d+)", agent
        )
    }
    expected_signals = manifest["expectedSignals"]
    assert all(signal in weights for signal in expected_signals)
    assert sum(weights[signal] for signal in expected_signals) >= manifest[
        "expectedMinimumRiskScore"
    ]
    assert manifest["expectedVerdict"] == "high_risk_behavior_observed"


def test_native_fixture_builds_as_a_windows_pe_without_executing_it(tmp_path) -> None:
    go = shutil.which("go")
    if go is None:
        pytest.skip("Go compiler is not installed")

    output = tmp_path / "prewise-native-fixture.exe"
    env = os.environ.copy()
    env.update({"GOOS": "windows", "GOARCH": "amd64", "CGO_ENABLED": "0"})
    result = subprocess.run(
        [
            go,
            "build",
            "-trimpath",
            "-ldflags=-s -w",
            f"-o={output}",
            str(FIXTURE_SOURCE),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=240,
        env=env,
        cwd=ROOT,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert output.read_bytes()[:2] == b"MZ"
    assert output.stat().st_size > 100_000
