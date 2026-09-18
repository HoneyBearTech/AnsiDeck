import yaml

from app.models import Inventory, InventoryGroup


def render_inventory_yaml(inventory: Inventory, group: InventoryGroup | None) -> str:
    hosts = group.hosts if group is not None else inventory.hosts
    hosts_block = {host.hostname: (dict(host.vars) or None) for host in hosts}

    if group is not None:
        data = {"all": {"children": {group.name: {"hosts": hosts_block}}}}
    else:
        data = {"all": {"hosts": hosts_block}}

    return yaml.safe_dump(data, sort_keys=False)
