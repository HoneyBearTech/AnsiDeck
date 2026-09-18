import yaml

from app.inventory_render import render_inventory_yaml
from app.models import Inventory, InventoryGroup, InventoryHost


def test_render_all_hosts_when_no_group() -> None:
    inventory = Inventory(id=1, name="homelab")
    inventory.hosts = [
        InventoryHost(id=1, inventory_id=1, hostname="host1", vars={"ansible_user": "deploy"}),
        InventoryHost(id=2, inventory_id=1, hostname="host2", vars={}),
    ]

    rendered = yaml.safe_load(render_inventory_yaml(inventory, None))

    assert set(rendered["all"]["hosts"].keys()) == {"host1", "host2"}
    assert rendered["all"]["hosts"]["host1"] == {"ansible_user": "deploy"}
    assert rendered["all"]["hosts"]["host2"] is None


def test_render_group_hosts_only() -> None:
    inventory = Inventory(id=1, name="homelab")
    group = InventoryGroup(id=1, inventory_id=1, name="web")
    group.hosts = [InventoryHost(id=1, inventory_id=1, hostname="host1", vars={})]

    rendered = yaml.safe_load(render_inventory_yaml(inventory, group))

    assert list(rendered["all"]["children"].keys()) == ["web"]
    assert list(rendered["all"]["children"]["web"]["hosts"].keys()) == ["host1"]
