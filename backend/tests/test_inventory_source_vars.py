"""Which Ansible settings a dynamic source may hand to runs: where and as whom to connect, never
how. Anything else from a source is dropped, both when a refresh stores its snapshot and when a
run renders one stored before the rule existed."""

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from app.inventory_render import merge, render, source_var_problem
from app.inventory_sources import normalise

ANSIBLE_INVENTORY = Path(sys.executable).with_name("ansible-inventory")
ANSIBLE = Path(sys.executable).with_name("ansible")


def _export(tmp_path: Path, inventory: dict) -> bytes:
    """What ansible-inventory --list --export prints for this data (a refresh's raw output)."""
    source = tmp_path / "source.yml"
    source.write_text(yaml.safe_dump(inventory))
    return subprocess.run(
        [str(ANSIBLE_INVENTORY), "-i", str(source), "--list", "--export"],
        capture_output=True,
        check=True,
    ).stdout


def _proxy(marker: Path) -> str:
    return f'-o ProxyCommand="touch {marker}"'


def _source(marker: Path) -> dict:
    return {
        "all": {
            "vars": {"ansible_python_interpreter": "/tmp/py", "site": "fra1"},
            "children": {
                "switches": {
                    "vars": {"ansible_shell_executable": "/tmp/sh", "rack": "r1"},
                    "hosts": {
                        "sw1.example": {
                            "ansible_host": "127.0.0.1",
                            "ansible_port": 9,
                            "ansible_user": "netops",
                            "ansible_connection": "ssh",
                            "ansible_ssh_common_args": _proxy(marker),
                            "serial": "ABC123",
                        },
                        "sw2.example": {"ansible_connection": "local"},
                    },
                }
            },
        }
    }


@pytest.mark.parametrize(
    ("key", "value", "allowed"),
    [
        ("ansible_host", "10.0.0.1", True),
        ("ansible_port", 2222, True),
        ("ansible_user", "deploy", True),
        ("ansible_ssh_host", "10.0.0.1", True),
        ("ansible_network_os", "cisco.ios.ios", True),
        ("ansible_connection", "ssh", True),
        ("ansible_connection", "network_cli", True),
        ("ansible_connection", "local", False),
        ("ansible_connection", "docker", False),
        ("ansible_ssh_common_args", "-o Foo=bar", False),
        ("ansible_ssh_extra_args", "-o Foo=bar", False),
        ("ansible_ssh_executable", "/bin/ssh", False),
        ("ansible_python_interpreter", "/usr/bin/python3", False),
        ("ansible_become_exe", "sudo", False),
        ("ansible_ssh_private_key_file", "/tmp/k", False),
        ("ANSIBLE_SSH_COMMON_ARGS", "-o Foo=bar", False),
        ("site", "anything", True),
        ("my_ansible_note", "anything", True),
    ],
)
def test_only_where_and_as_whom_to_connect(key: str, value: object, allowed: bool) -> None:
    assert (source_var_problem(key, value) is None) is allowed


def test_a_refresh_drops_settings_a_source_may_not_set(tmp_path: Path) -> None:
    marker = tmp_path / "marker"
    snapshot, warnings = normalise(_export(tmp_path, _source(marker)), [])
    sw1 = snapshot["hosts"]["sw1.example"]
    assert sw1 == {
        "ansible_host": "127.0.0.1",
        "ansible_port": 9,
        "ansible_user": "netops",
        "ansible_connection": "ssh",
        "serial": "ABC123",
    }
    assert snapshot["hosts"]["sw2.example"] == {}
    assert snapshot["groups"]["switches"]["vars"] == {"rack": "r1"}
    assert snapshot["vars"] == {"site": "fra1"}
    joined = "\n".join(warnings)
    for dropped in (
        "host sw1.example: dropped ansible_ssh_common_args",
        "host sw2.example: dropped ansible_connection",
        "group switches: dropped ansible_shell_executable",
        "group all: dropped ansible_python_interpreter",
    ):
        assert dropped in joined


def test_a_static_hosts_own_settings_are_kept_quietly(tmp_path: Path) -> None:
    """The inventory's own hosts are fed to the plugins and come back with their own vars.
    Those connection settings are the inventory's (merge puts them back), so the drop is quiet."""
    exported = _export(tmp_path, {"all": {"hosts": {"web1": {"ansible_connection": "local"}}}})
    snapshot, warnings = normalise(exported, ["web1"])
    assert snapshot["hosts"]["web1"] == {} and warnings == []
    static = {"hosts": {"web1": {"ansible_connection": "local"}}, "groups": {}}
    assert merge(static, snapshot)["hosts"]["web1"] == {"ansible_connection": "local"}


def test_a_snapshot_stored_before_the_rule_is_filtered_when_a_run_renders_it(
    tmp_path: Path,
) -> None:
    """End to end: the rendered inventory is handed to real Ansible, which must not run the
    source's ProxyCommand."""
    marker = tmp_path / "marker"
    old_snapshot = {
        "vars": {"ansible_python_interpreter": "/tmp/py"},
        "hosts": {
            "sw1.example": {
                "ansible_host": "127.0.0.1",
                "ansible_port": 9,
                "ansible_ssh_common_args": _proxy(marker),
            }
        },
        "groups": {
            "switches": {
                "hosts": ["sw1.example"],
                "children": [],
                "vars": {"ansible_ssh_executable": "/tmp/ssh"},
            }
        },
        "static_hosts": [],
    }
    rendered = render(merge({"hosts": {}, "groups": {}}, old_snapshot))
    hosts = tmp_path / "hosts.yml"
    hosts.write_text(rendered)
    subprocess.run(
        [
            str(ANSIBLE),
            "-i",
            str(hosts),
            "sw1.example",
            "-m",
            "ping",
            "-e",
            "ansible_ssh_timeout=3",
        ],
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert not marker.exists()
    for key in ("ansible_ssh_common_args", "ansible_ssh_executable", "ansible_python_interpreter"):
        assert key not in rendered
