"""Headless raw-function barrier verification tests."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.runner.runtime_verifier import verify_function

runner = CliRunner()


def test_headless_verifier_proves_threaded_lost_update(tmp_path: Path) -> None:
    """Dynamically import a raw function and prove its shared-dict lost update."""
    target = tmp_path / "vulnerable.py"
    target.write_text(
        "import time\n\nshared = {'count': 0}\n\ndef update_shared_state():\n"
        "    current = shared['count']\n    time.sleep(0.005)\n    shared['count'] = current + 1\n",
        encoding="utf-8",
    )

    result = verify_function(target, "update_shared_state", workers=12)

    assert result["execution_mode"] == "threading"
    assert result["expected_value"] == 12
    assert result["actual_value"] < result["expected_value"]
    assert result["invariant_violated"] is True


def test_verify_cli_headless_prints_empirical_proof(tmp_path: Path) -> None:
    """The public CLI exposes headless verification without HTTP infrastructure."""
    target = tmp_path / "vulnerable.py"
    target.write_text(
        "import time\nshared = {'count': 0}\ndef increment():\n"
        "    value = shared['count']\n    time.sleep(0.005)\n    shared['count'] = value + 1\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["verify", str(target), "--headless", "--function", "increment", "--workers", "8"])

    assert result.exit_code == 1
    assert "INVARIANT VIOLATION PROVEN" in result.stdout
    assert "Expected value" in result.stdout
