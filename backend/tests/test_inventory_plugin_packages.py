"""The image ships the Python packages that the AWS and Proxmox inventory plugins (and the
Proxmox modules) need: the plugins load and get as far as the network. Their endpoints here
are a closed local port, so nothing leaves the machine."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

CONFIGS = {
    "x.aws_ec2.yml": (
        "plugin: amazon.aws.aws_ec2\nregions: [eu-central-1]\nendpoint_url: http://127.0.0.1:9\n",
        "Could not connect to the endpoint URL",
    ),
    "x.proxmox.yml": (
        (
            "plugin: community.proxmox.proxmox\nurl: http://127.0.0.1:9\nuser: root@pam\n"
            "password: not-a-secret\nvalidate_certs: false\n"
        ),
        "Connection refused",
    ),
}


@pytest.mark.parametrize("name", sorted(CONFIGS))
def test_the_cloud_inventory_plugins_have_their_python_packages(tmp_path: Path, name: str) -> None:
    config, reached_the_network = CONFIGS[name]
    (tmp_path / name).write_text(config)
    env = {
        "PATH": f"{Path(sys.executable).parent}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "ANSIBLE_HOME": str(tmp_path / "ansible"),
        "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "not-a-secret",
        "AWS_EC2_METADATA_DISABLED": "true",
    }
    result = subprocess.run(
        ["ansible-inventory", "-i", name, "--list"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    output = result.stdout + result.stderr
    assert reached_the_network in output, output[-2000:]
    assert "required Python library" not in output and "No module named" not in output


def test_the_proxmox_modules_library_is_there() -> None:
    import proxmoxer  # noqa: F401 - the community.proxmox modules import it
