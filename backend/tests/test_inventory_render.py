"""The inventory a run sees, read back through ansible's own YAML inventory plugin."""

import pytest
from ansible._internal._datatag._tags import TrustedAsTemplate
from ansible.inventory.manager import InventoryManager
from ansible.parsing.dataloader import DataLoader

from app.inventory_render import (
    group_problem,
    hostname_problem,
    merge,
    render,
    static_data,
    static_problems,
)
from app.models import Inventory, InventoryGroup, InventoryHost

STATIC = {
    "hosts": {"web1": {"role": "web", "tmpl": "{{ 1 + 1 }}"}, "db1": {}},
    "groups": {"web": ["web1"], "manual": ["db1"], "empty": []},
}


def load(text: str, tmp_path) -> InventoryManager:
    path = tmp_path / "hosts.yml"
    path.write_text(text)
    return InventoryManager(loader=DataLoader(), sources=[str(path)])


def members(inventory: InventoryManager) -> dict[str, list[str]]:
    return {
        name: sorted(host.name for host in group.get_hosts())
        for name, group in inventory.groups.items()
    }


def test_every_group_is_visible_to_a_run(tmp_path) -> None:
    inventory = load(render(merge(STATIC)), tmp_path)
    assert sorted(h.name for h in inventory.get_hosts()) == ["db1", "web1"]
    assert members(inventory) == {
        "all": ["db1", "web1"],
        "ungrouped": [],
        "web": ["web1"],
        "manual": ["db1"],
        "empty": [],
    }
    assert inventory.get_host("web1").get_vars()["role"] == "web"


def test_a_target_group_keeps_the_tree_but_only_its_hosts(tmp_path) -> None:
    inventory = load(render(merge(STATIC), "web"), tmp_path)
    assert [h.name for h in inventory.get_hosts()] == ["web1"]
    assert members(inventory)["manual"] == []  # still there, so `hosts: manual` is valid


def test_a_target_group_includes_the_hosts_of_its_child_groups(tmp_path) -> None:
    snapshot = {
        "vars": {},
        "hosts": {"nb1": {}, "nb2": {}},
        "groups": {
            "eu": {"hosts": ["nb1"], "children": ["eu_west"], "vars": {}},
            "eu_west": {"hosts": ["nb2"], "children": [], "vars": {}},
        },
    }
    inventory = load(render(merge(STATIC, snapshot), "eu"), tmp_path)
    assert sorted(h.name for h in inventory.get_hosts()) == ["nb1", "nb2"]


def test_static_data_wins_and_source_strings_are_never_templates(tmp_path) -> None:
    snapshot = {
        "vars": {"site": "{{ site_tmpl }}"},
        "static_hosts": ["web1", "db1", "gone1"],
        "hosts": {
            "web1": {"role": "from-source", "note": "{{ lookup('pipe', 'id') }}"},
            "nb1": {"nested": {"{{ key }}": ["{{ item }}"]}},
            "gone1": {},
        },
        "groups": {
            "web": {"hosts": ["nb1", "web1"], "children": [], "vars": {"gv": "{{ g }}"}},
            # web1 was in manual when the source ran; the inventory's own groups decide.
            "manual": {"hosts": ["web1", "gone1"], "children": [], "vars": {}},
        },
    }
    inventory = load(render(merge(STATIC, snapshot)), tmp_path)
    assert sorted(h.name for h in inventory.get_hosts()) == ["db1", "nb1", "web1"]
    assert members(inventory)["web"] == ["nb1", "web1"]
    assert members(inventory)["manual"] == ["db1"]

    web1 = inventory.get_host("web1").get_vars()
    assert web1["role"] == "web"  # the static value wins
    assert TrustedAsTemplate.is_tagged_on(web1["tmpl"])  # static stays templatable
    assert not TrustedAsTemplate.is_tagged_on(web1["note"])
    nested = inventory.get_host("nb1").get_vars()["nested"]
    (key,) = nested
    assert key == "{{ key }}" and not TrustedAsTemplate.is_tagged_on(key)
    assert not TrustedAsTemplate.is_tagged_on(nested[key][0])
    group_var = inventory.groups["web"].get_vars()["gv"]
    assert not TrustedAsTemplate.is_tagged_on(group_var)
    all_var = inventory.groups["all"].get_vars()["site"]
    assert all_var == "{{ site_tmpl }}" and not TrustedAsTemplate.is_tagged_on(all_var)


def test_an_unknown_target_group_is_refused() -> None:
    with pytest.raises(KeyError):
        render(merge(STATIC), "nope")


def test_static_data_reads_the_inventory() -> None:
    inventory = Inventory(name="i")
    web = InventoryGroup(name="web")
    inventory.groups = [web]
    inventory.hosts = [
        InventoryHost(hostname="a", vars={"x": 1}, groups=[web]),
        InventoryHost(hostname="b", vars=None),
    ]
    assert static_data(inventory) == {
        "hosts": {"a": {"x": 1}, "b": {}},
        "groups": {"web": ["a"]},
    }


@pytest.mark.parametrize(
    "name",
    ["web1", "web-1.example.com", "10.0.0.1", "fe80::1", "fe80::1%eth0", "host_2", "2001:db8::5"],
)
def test_good_hostnames(name: str) -> None:
    assert hostname_problem(name) is None


@pytest.mark.parametrize(
    "name",
    ["db:5432", "10.0.0.1:22", "[::1]:22", "web[1:3]", "web[a:c].x", "a b", "", "x" * 256,
     "{{ x }}", "a,b", "-x", ".x", "h\n", "[::1]"],
)  # fmt: skip
def test_hostnames_ansible_would_read_differently(name: str) -> None:
    assert hostname_problem(name) is not None


@pytest.mark.parametrize("name", ["web", "web-servers", "eu.west", "_x", "G1"])
def test_good_group_names(name: str) -> None:
    assert group_problem(name) is None


@pytest.mark.parametrize("name", ["all", "ungrouped", "", "a b", "a:b", "-x", "{{x}}", "x" * 256])
def test_bad_group_names(name: str) -> None:
    assert group_problem(name) is not None


def test_legacy_names_are_reported() -> None:
    problems = static_problems({"hosts": {"db:5432": {}}, "groups": {"all": []}})
    assert problems == [
        "host 'db:5432' must not include a port (set ansible_port instead)",
        "group 'all' 'all' is reserved by ansible",
    ]
