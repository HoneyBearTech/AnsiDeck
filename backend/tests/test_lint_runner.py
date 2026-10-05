"""Playbook checks in the run process (app.run_worker.run_lint) with the real ansible-lint."""

import io
import json
import sys
import tarfile
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import run_worker

CLEAN = """\
- name: Clean
  hosts: all
  gather_facts: false
  tasks:
    - name: Say hi
      ansible.builtin.debug:
        msg: hi
"""

UNTIDY = """\
- hosts: all
  tasks:
    - shell: echo hi
"""


def _tar(files: dict[str, str], links: dict[str, str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)
    return buffer.getvalue()


def _lint(monkeypatch, *, content=None, repo=None, playbook=None, max_findings=500) -> dict:
    messages: list[dict] = []
    job: dict = {"prefix": "ansideck-lint-test-", "max_findings": max_findings}
    if repo is not None:
        monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(_tar(repo))))
        job["project"] = {"playbook": playbook}
    else:
        job["content"] = content
    run_worker.run_lint(job, messages.append)
    assert messages[0]["type"] == "started"
    assert not Path(messages[0]["private_data_dir"]).exists()  # cleaned up
    result = next(m for m in messages if m["type"] == "lint_result")
    assert messages[-1] == {
        "type": "result",
        "status": "failed" if result["error"] else "successful",
        "rc": result["rc"],
    }
    assert "ansideck-lint-test-" not in json.dumps(result)  # no temp paths leak
    return result


def _rules(result: dict) -> set[str]:
    return {f["rule"] for f in result["findings"]}


def test_a_clean_playbook_has_no_findings(monkeypatch) -> None:
    result = _lint(monkeypatch, content=CLEAN)
    assert (result["rc"], result["findings"], result["error"]) == (0, [], None)
    assert result["version"].split(".")[0].isdigit()


def test_findings_carry_rule_level_line_and_a_link(monkeypatch) -> None:
    result = _lint(monkeypatch, content=UNTIDY)
    assert result["rc"] == 2
    assert {"name[play]", "name[missing]", "fqcn[action-core]", "no-changed-when"} <= _rules(result)
    fqcn = next(f for f in result["findings"] if f["rule"] == "fqcn[action-core]")
    assert fqcn == {
        "rule": "fqcn[action-core]",
        "level": "error",
        "message": "Use FQCN for builtin module actions (shell).",
        "details": "Use `ansible.builtin.shell` or `ansible.legacy.shell` instead.",
        "path": "playbook.yml",
        "line": 3,
        "column": 7,
        "url": "https://docs.ansible.com/projects/lint/rules/fqcn/",
    }
    lines = [f["line"] for f in result["findings"]]
    assert lines == sorted(lines)


def test_broken_yaml_is_an_error_finding_not_a_failure(monkeypatch) -> None:
    result = _lint(monkeypatch, content="- hosts: all\n  tasks:\n   - name: x\n     debug: [\n")
    assert result["error"] is None
    (finding,) = result["findings"]
    assert finding["rule"] == "load-failure[yaml]"
    assert finding["level"] == "error"  # ansible-lint itself calls it "minor"


def test_a_missing_role_is_reported_without_temp_paths(monkeypatch) -> None:
    result = _lint(monkeypatch, content="- name: P\n  hosts: all\n  roles:\n    - nosuchrole\n")
    (finding,) = result["findings"]
    assert finding["rule"] == "syntax-check[specific]"
    assert "nosuchrole" in finding["message"]
    assert tempfile.gettempdir() not in finding["message"]


def test_vault_values_and_missing_vars_files_check_fine(monkeypatch) -> None:
    playbook = (
        "- name: P\n  hosts: all\n  vars_files:\n    - missing.yml\n  vars:\n"
        "    secret: !vault |\n      $ANSIBLE_VAULT;1.1;AES256\n      3132\n  tasks:\n"
        "    - name: T\n      ansible.builtin.debug:\n        msg: '{{ secret }}'\n"
    )
    assert _lint(monkeypatch, content=playbook)["findings"] == []


def test_findings_are_capped_and_the_total_kept(monkeypatch) -> None:
    result = _lint(monkeypatch, content=UNTIDY, max_findings=2)
    assert len(result["findings"]) == 2
    assert result["total"] > 2
    assert result["truncated"] is True


REPO_PLAYBOOK = "- name: Site\n  hosts: all\n  roles:\n    - web\n"
ROLE_TASKS = "- shell: echo role\n"


def test_a_repository_is_checked_with_its_config_roles_and_rules(monkeypatch) -> None:
    rule = (
        "from ansiblelint.rules import AnsibleLintRule\n\n\n"
        "class Marker(AnsibleLintRule):\n"
        "    id = 'marker'\n    description = 'every task'\n    shortdesc = 'marker'\n"
        "    tags = ['custom']\n\n"
        "    def matchtask(self, task, file=None):\n        return True\n"
    )
    result = _lint(
        monkeypatch,
        repo={
            "playbooks/site.yml": REPO_PLAYBOOK,
            "roles/web/tasks/main.yml": ROLE_TASKS,
            ".ansible-lint": "skip_list:\n  - name[missing]\nrulesdir:\n  - rules\n"
            "use_default_rules: true\n",
            "rules/marker.py": rule,
        },
        playbook="playbooks/site.yml",
    )
    rules = _rules(result)
    assert "name[missing]" not in rules  # the repository's skip_list applies
    assert {"fqcn[action-core]", "marker"} <= rules  # its role is found; its own rule loads
    assert {f["path"] for f in result["findings"]} == {"roles/web/tasks/main.yml"}


def test_a_repository_config_cannot_make_ansible_lint_rewrite_and_hide(monkeypatch) -> None:
    # write_list applies even without --fix: the role file would be rewritten and the
    # "fixed" findings dropped from the report.
    result = _lint(
        monkeypatch,
        repo={
            "playbooks/site.yml": REPO_PLAYBOOK,
            "roles/web/tasks/main.yml": ROLE_TASKS,
            ".ansible-lint": "write_list:\n  - all\n",
        },
        playbook="playbooks/site.yml",
    )
    assert {"fqcn[action-core]", "command-instead-of-shell"} <= _rules(result)


def test_a_config_planted_above_the_project_is_ignored(monkeypatch, tmp_path) -> None:
    # Without -c, ansible-lint walks up parent directories (to the shared /tmp) for a config.
    (tmp_path / ".ansible-lint").write_text("skip_list:\n  - fqcn\n  - name\n")
    real_mkdtemp = tempfile.mkdtemp
    monkeypatch.setattr(
        run_worker.tempfile,
        "mkdtemp",
        lambda prefix, dir: real_mkdtemp(prefix=prefix, dir=tmp_path),
    )
    assert {"fqcn[action-core]", "name[missing]"} <= _rules(_lint(monkeypatch, content=UNTIDY))


def test_an_invalid_repository_config_explains_itself(monkeypatch) -> None:
    result = _lint(
        monkeypatch,
        repo={"site.yml": CLEAN, ".ansible-lint": "no_such_option: true\n"},
        playbook="site.yml",
    )
    assert result["rc"] == 3
    assert result["error"].startswith("ansible-lint's configuration is invalid: ")
    assert "no_such_option" in result["error"]
    assert "\x1b" not in result["error"]
    assert result["findings"] == []


def test_an_excluded_playbook_is_still_checked_when_named(monkeypatch) -> None:
    # ansible-lint checks a file named on its command line even if exclude_paths covers it.
    result = _lint(
        monkeypatch,
        repo={"playbooks/site.yml": UNTIDY, ".ansible-lint": "exclude_paths:\n  - playbooks/\n"},
        playbook="playbooks/site.yml",
    )
    assert "fqcn[action-core]" in _rules(result)


def test_ansible_lint_failing_outright_is_an_error(monkeypatch, tmp_path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "ansible-lint").write_text("#!/bin/sh\necho 'Traceback: boom' >&2\nexit 1\n")
    (fake_bin / "ansible-lint").chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(fake_bin / "python"))
    result = _lint(monkeypatch, content=CLEAN)
    assert result["error"] == "ansible-lint failed (exit 1): Traceback: boom"


def test_unreadable_output_is_an_error(monkeypatch, tmp_path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "ansible-lint").write_text("#!/bin/sh\necho 'not json'\nexit 2\n")
    (fake_bin / "ansible-lint").chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(fake_bin / "python"))
    assert _lint(monkeypatch, content=CLEAN)["error"] == "ansible-lint's output couldn't be read"


def test_lint_config_strips_dangerous_keys_and_outside_rules(tmp_path) -> None:
    import yaml

    project = tmp_path / "project"
    (project / "rules").mkdir(parents=True)
    (project / ".ansible-lint").write_text(
        yaml.safe_dump(
            {
                "skip_list": ["fqcn"],
                "write_list": ["all"],
                "sarif_file": "/etc/passwd",
                "cache_dir": "/tmp/x",
                "extra_vars": {"a": 1},
                "offline": False,
                "project_dir": "/",
                "rulesdir": ["rules", "/etc", "../..", "~/x", "$HOME/x", 5, ""],
            }
        )
    )
    path = run_worker.lint_config(project)
    assert path == str(project / ".ansible-lint")
    assert yaml.safe_load(Path(path).read_text()) == {"skip_list": ["fqcn"], "rulesdir": ["rules"]}


def test_lint_config_never_writes_through_a_link(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "shared.yml").write_text("write_list: [all]\nskip_list: [fqcn]\n")
    (project / ".ansible-lint").symlink_to("shared.yml")
    run_worker.lint_config(project)
    assert (project / "shared.yml").read_text() == "write_list: [all]\nskip_list: [fqcn]\n"
    assert not (project / ".ansible-lint").is_symlink()


def test_lint_config_without_a_config_and_with_bad_ones(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    assert run_worker.lint_config(project) == "/dev/null"
    outside = tmp_path / "outside.yml"
    outside.write_text("skip_list: [fqcn]\n")
    (project / ".ansible-lint").symlink_to(outside)
    assert run_worker.lint_config(project) == "/dev/null"  # a link out of the repo is ignored
    (project / ".ansible-lint").unlink()
    (project / ".ansible-lint").write_text("- a list\n")
    with pytest.raises(RuntimeError, match="not a mapping"):
        run_worker.lint_config(project)
    (project / ".ansible-lint").write_text("a: [\n")
    with pytest.raises(RuntimeError, match="can't be read"):
        run_worker.lint_config(project)


def test_lint_findings_skips_outside_files_and_odd_entries() -> None:
    issues = [
        "not a dict",
        {"check_name": "x", "location": {"path": "/galaxy/collections/a.yml"}},
        {"check_name": "y", "location": {"path": "../elsewhere.yml"}},
        {
            "check_name": "z",
            "severity": "minor",
            "url": "javascript:alert(1)",
            "location": {"path": "other.yml", "lines": {"begin": 4}},
        },
        {"check_name": "w", "severity": "major", "location": {"path": "playbook.yml"}},
    ]
    findings, total, external = run_worker.lint_findings(issues, "playbook.yml", 10, str)
    assert (total, external) == (2, 2)
    assert [(f["rule"], f["path"], f["line"], f["level"], f["url"]) for f in findings] == [
        ("w", "playbook.yml", 1, "error", None),
        ("z", "other.yml", 4, "warning", None),
    ]
    assert run_worker.lint_findings({"not": "a list"}, "playbook.yml", 10, str) == ([], 0, 0)


def test_lint_in_worker_runs_the_check_in_a_child_with_a_clean_environment(monkeypatch) -> None:
    from app.run_executor import RunRefused, lint_in_worker
    from app.subprocess_env import clean_env

    monkeypatch.setenv("ANSIDECK_TEST_SECRET", "must-not-reach-the-child")
    job = {"prefix": "ansideck-lint-", "max_findings": 500}
    result = lint_in_worker({**job, "content": UNTIDY}, clean_env())
    assert result is not None
    assert "fqcn[action-core]" in _rules(result)

    repo = _tar({"site.yml": REPO_PLAYBOOK, "roles/web/tasks/main.yml": ROLE_TASKS})
    site = {**job, "project": {"playbook": "site.yml"}}
    result = lint_in_worker(site, clean_env(), stdin_tail=repo)
    assert {f["path"] for f in result["findings"]} == {"roles/web/tasks/main.yml"}

    with pytest.raises(RunRefused, match="not a file in the repository"):
        lint_in_worker({**job, "project": {"playbook": "nope.yml"}}, clean_env(), stdin_tail=repo)
