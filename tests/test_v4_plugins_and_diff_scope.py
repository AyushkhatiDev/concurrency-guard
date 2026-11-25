"""Integration tests for trusted plugin loading and committed diff scope."""
import json
import subprocess
from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cli import app


def test_plugin_config_requires_opt_in_and_uses_declared_metadata(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[tool.cguard]\nplugins = ["rule.py"]\n')
    (tmp_path / "sample.py").write_text("answer = 42\n")
    (tmp_path / "rule.py").write_text("""
from concurrency_guard.scanner.ast_rules import ASTFinding
class Rule:
    rule_id = "ACME-001"
    severity = "MEDIUM"
    cwe = "CWE-833"
    def check(self, module):
        if module.path.name == "sample.py":
            return [ASTFinding(self.rule_id, str(module.path), 1, "<module>", "Example", "Review")]
        return []
PLUGIN = Rule()
""")
    runner = CliRunner()
    args = ["scan", str(tmp_path), "--no-cache", "--format", "sarif"]
    assert runner.invoke(app, args).exit_code == 0
    enabled = runner.invoke(app, [*args, "--allow-plugins"])
    assert enabled.exit_code == 1, enabled.output
    run = json.loads(enabled.stdout)["runs"][0]
    assert run["results"][0]["ruleId"] == "ACME-001"
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "ACME-001")
    assert rule["defaultConfiguration"]["level"] == "warning"
    assert "CWE-833" in rule["properties"]["tags"]


def test_invalid_plugin_exits_with_readable_error(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[tool.cguard]\nplugins = ["../escape.py"]\n')
    result = CliRunner().invoke(app, ["scan", str(tmp_path), "--allow-plugins", "--no-cache"])
    assert result.exit_code == 2
    assert "Failed to load rule plugin" in result.output


def test_diff_includes_only_changed_files_and_transitive_importers(tmp_path: Path) -> None:
    def git(*args: str) -> None:
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)

    unsafe = """
async def run():
    try:
        await work()
    except BaseException:
        pass
"""
    git("init")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "Test")
    for filename, imports in (("leaf", ""), ("middle", "import leaf\n"),
                              ("caller", "import middle\n"), ("unrelated", "")):
        (tmp_path / f"{filename}.py").write_text(imports + unsafe)
    git("add", ".")
    git("commit", "-m", "baseline")
    git("tag", "base")
    (tmp_path / "leaf.py").write_text(unsafe + "\nvalue = 1\n")
    git("add", "leaf.py")
    git("commit", "-m", "update leaf")
    result = CliRunner().invoke(app, [
        "scan", str(tmp_path), "--diff-base", "base", "--no-cache", "--format", "json",
    ])
    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["scanned_files"] == 3
    assert {Path(f["filename"]).name for f in payload["findings"]} == {
        "leaf.py", "middle.py", "caller.py",
    }
