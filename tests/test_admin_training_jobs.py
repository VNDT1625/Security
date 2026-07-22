from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks, HTTPException

from backend.routers import admin


@pytest.mark.asyncio
async def test_spec_execution_is_explicitly_disabled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    specs_dir = tmp_path / "specs"
    tasks_file = specs_dir / "example" / "tasks.md"
    tasks_file.parent.mkdir(parents=True)
    tasks_file.write_text("- [ ] real work\n", encoding="utf-8")
    monkeypatch.setattr(admin, "SPECS_DIR", specs_dir)

    with pytest.raises(HTTPException) as exc:
        await admin.execute_spec_tasks(admin.SpecExecutionRequest(specId="example"))

    assert exc.value.status_code == 501
    assert "no real task executor" in str(exc.value.detail)
    assert tasks_file.read_text(encoding="utf-8") == "- [ ] real work\n"


@pytest.mark.asyncio
async def test_training_rejects_missing_deployment_dataset_before_creating_job(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(admin, "TRAINING_DATA_DIR", tmp_path / "missing-data")
    missing_dataset = admin.TRAINING_DATA_DIR / "not-installed.csv"

    with pytest.raises(HTTPException) as exc:
        await admin.train_models(
            admin.ModelTrainingRequest(dataPath=str(missing_dataset), models=["text"]),
            BackgroundTasks(),
            db=SimpleNamespace(),
        )

    assert exc.value.status_code == 503
    assert "not installed" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_training_process_failure_is_terminal_and_runs_off_event_loop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    script = tmp_path / "train.py"
    script.write_text("# test executor\n", encoding="utf-8")
    monkeypatch.setattr(admin, "MODEL_CANDIDATE_DIR", tmp_path / "candidates")
    monkeypatch.setattr(
        admin,
        "TRAINING_SCRIPTS",
        {"text": (script, ["--train", "{data}"], "model.onnx")},
    )

    updates: list[dict] = []
    monkeypatch.setattr(admin, "_update_job", lambda _job_id, **fields: updates.append(fields))
    monkeypatch.setattr(admin, "_add_job_event", lambda *_args, **_kwargs: None)

    calls: list[object] = []

    async def fake_to_thread(function, *args, **kwargs):
        calls.append(function)
        return SimpleNamespace(returncode=2, stdout="", stderr="bad dataset")

    monkeypatch.setattr(admin.asyncio, "to_thread", fake_to_thread)

    await admin.run_model_training("job-1", str(tmp_path / "dataset.csv"), ["text"])

    assert calls == [admin.subprocess.run]
    assert updates[-1]["status"] == "failed"
    assert updates[-1]["result"]["results"] == [
        {"model": "text", "status": "failed", "error": "bad dataset"}
    ]
    assert "bad dataset" in updates[-1]["error"]


@pytest.mark.asyncio
async def test_training_does_not_claim_success_without_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    script = tmp_path / "train.py"
    script.write_text("# test executor\n", encoding="utf-8")
    monkeypatch.setattr(admin, "MODEL_CANDIDATE_DIR", tmp_path / "candidates")
    monkeypatch.setattr(
        admin,
        "TRAINING_SCRIPTS",
        {"text": (script, [], "expected.onnx")},
    )

    updates: list[dict] = []
    monkeypatch.setattr(admin, "_update_job", lambda _job_id, **fields: updates.append(fields))
    monkeypatch.setattr(admin, "_add_job_event", lambda *_args, **_kwargs: None)

    async def fake_to_thread(_function, *_args, **_kwargs):
        return SimpleNamespace(returncode=0, stdout='{"metrics": {"test": {"f1": 0.9}}}', stderr="")

    monkeypatch.setattr(admin.asyncio, "to_thread", fake_to_thread)

    await admin.run_model_training("job-2", str(tmp_path / "dataset.csv"), ["text"])

    assert updates[-1]["status"] == "failed"
    assert "did not produce expected.onnx" in updates[-1]["error"]


@pytest.mark.asyncio
async def test_training_missing_executor_is_failed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(admin, "MODEL_CANDIDATE_DIR", tmp_path / "candidates")
    monkeypatch.setattr(admin, "TRAINING_SCRIPTS", {})
    updates: list[dict] = []
    monkeypatch.setattr(admin, "_update_job", lambda _job_id, **fields: updates.append(fields))
    monkeypatch.setattr(admin, "_add_job_event", lambda *_args, **_kwargs: None)

    await admin.run_model_training("job-missing", str(tmp_path / "dataset.csv"), ["text"])

    assert updates[-1]["status"] == "failed"
    assert "executor is not installed" in updates[-1]["error"]


@pytest.mark.asyncio
async def test_training_timeout_is_failed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    script = tmp_path / "train.py"
    script.write_text("# test executor\n", encoding="utf-8")
    monkeypatch.setattr(admin, "MODEL_CANDIDATE_DIR", tmp_path / "candidates")
    monkeypatch.setattr(
        admin,
        "TRAINING_SCRIPTS",
        {"text": (script, [], "expected.onnx")},
    )
    updates: list[dict] = []
    monkeypatch.setattr(admin, "_update_job", lambda _job_id, **fields: updates.append(fields))
    monkeypatch.setattr(admin, "_add_job_event", lambda *_args, **_kwargs: None)

    async def fake_to_thread(_function, *_args, **_kwargs):
        raise admin.subprocess.TimeoutExpired(cmd="train", timeout=1800)

    monkeypatch.setattr(admin.asyncio, "to_thread", fake_to_thread)

    await admin.run_model_training("job-timeout", str(tmp_path / "dataset.csv"), ["text"])

    assert updates[-1]["status"] == "failed"
    assert "timed out after 1800 seconds" in updates[-1]["error"]


def test_failed_job_payload_preserves_terminal_status_and_error() -> None:
    job = SimpleNamespace(
        id="job-3",
        job_type="model_training",
        status="failed",
        current_step="Training failed",
        progress=100,
        message="Processed one model",
        error="text: timed out",
        result={"results": [{"model": "text", "status": "failed"}]},
    )

    payload = admin._job_payload(job)

    assert payload["status"] == "failed"
    assert payload["message"] == "text: timed out"
