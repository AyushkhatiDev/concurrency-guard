import json
import subprocess
from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cache.manager import dict_to_finding, finding_to_dict
from concurrency_guard.cli import app
from concurrency_guard.lsp import diagnostic_to_dict, finding_to_diagnostic
from concurrency_guard.report import compute_audit_metrics, render_html_report
from concurrency_guard.sarif import findings_to_sarif
from concurrency_guard.scanner.ast_rules import scan_source_code


def test_diff_matches_full_with_unchanged_helper(tmp_path: Path) -> None:
    def git(*args: str) -> None:
        subprocess.run(["git", "-C", str(tmp_path), *args], capture_output=True, check=True)

    git("init")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.invalid")
    (tmp_path / "helper.py").write_text("import asyncio\nlock = asyncio.Lock()\nasync def take():\n    async with lock: pass\n")
    caller = tmp_path / "caller.py"
    caller.write_text("from helper import lock, take\n")
    (tmp_path / "other.py").write_text("async def other():\n    try: await job()\n    except: pass\n")
    git("add", ".")
    git("commit", "-m", "base")
    caller.write_text(caller.read_text() + "async def run():\n    async with lock: await take()\n")
    git("add", ".")
    git("commit", "-m", "caller")
    args = ["scan", str(tmp_path), "--format", "json", "--no-cache"]
    runner = CliRunner()
    full = json.loads(runner.invoke(app, args).stdout)
    diff = json.loads(runner.invoke(app, [*args, "--diff-base", "HEAD~1"]).stdout)
    assert diff["scanned_files"] == 1
    assert diff["findings"] == [f for f in full["findings"] if Path(f["filename"]).name == "caller.py"]
    assert any(f["rule_id"] == "CG-032" for f in diff["findings"])


def test_evidence_round_trip_and_renderers(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    source = "async def run(db):\n    await asyncio.gather(load(db), save(db))\n"
    path.write_text(source)
    finding, = (f for f in scan_source_code(source, filename=str(path)) if f.rule_id == "CG-031")
    assert dict_to_finding(finding_to_dict(finding)) == finding
    result = findings_to_sarif([finding], tmp_path)["runs"][0]["results"][0]
    locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
    related = diagnostic_to_dict(finding_to_diagnostic(finding))["relatedInformation"]
    html = render_html_report(compute_audit_metrics([finding]), [finding])
    scan = CliRunner().invoke(app, ["scan", str(path), "--format", "json", "--no-cache"])
    steps = json.loads(scan.stdout)["findings"][0]["evidence"]
    for step, loc, info, raw in zip(finding.evidence, locations, related, steps):
        physical = loc["location"]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == "app.py"
        assert physical["region"] == {"startLine": step.line, "startColumn": step.column + 1}
        assert info["location"]["uri"] == path.as_uri()
        assert info["message"] == raw["message"] == step.message
        assert step.message in html
    assert len(locations) == len(steps) == len(related) == 3


def test_rule_reference() -> None:
    result = CliRunner().invoke(app, ["explain", "CG-031"])
    assert result.exit_code == 0
    for term in ("CWE-362", "AsyncSession", "Unsafe example", "Safe example", "Autofix: manual"):
        assert term in result.output
    assert CliRunner().invoke(app, ["explain", "CG-999"]).exit_code == 2
