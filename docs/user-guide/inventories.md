# Inventories

An inventory is the list of hosts a run targets, organised in groups, with variables. Operators and admins
edit them; everyone in the project can see them.

## Hosts and groups

**Inventories → New inventory** creates one (a name and an optional description). Open it to manage its
contents:

- **Add group**: group names use letters, digits, `.`, `_` and `-`; `all` and `ungrouped` are Ansible's own.
- **Add host**: the **hostname** is exactly what Ansible connects to: a DNS name or address, with no port
  (use the `ansible_port` var) and no ranges. **Vars (JSON)** holds the host's variables, such as
  `{"ansible_user": "deploy", "ansible_port": 2222}`. Tick the groups the host belongs to.
- **Edit** a host to change any of this; **Delete** a group (its hosts stay) or a host, after a confirmation.

A run sees the inventory's **whole group tree**, so a play with `hosts: web` runs on the `web` group, and
picking a group as a run's target narrows the run to that group's hosts. A run uses the inventory as it was
when the run was started: edits made while it waits in the queue don't change it.

## Group graph

**Group graph** on an inventory's page shows how its groups nest, including the groups its dynamic sources
add (see below), and which hosts each one holds. It shows names and counts only, never vars.

- **Groups** is a tree that starts with the groups that have no parent. Open a group to see the groups
  under it. A group under several parents appears under each of them, with "also under …" next to it. The
  count beside a group is its own hosts, not those of the groups below it. **Search groups** lists every
  group whose name matches, with its parents.
- **Pick a group** to see where it sits: its parent groups, the group, and its child groups (click one to
  move there). Below that are the hosts a run would reach by targeting this group: its own hosts and those
  of every group below it.
- The tree works with the keyboard: Tab into it, then use the arrow keys to move, open (→) and close (←),
  Home and End to jump, and Enter to pick a group. The page's address includes the picked group, so you
  can link to it.


Project admins can add **dynamic sources** to an inventory: the config of an Ansible inventory plugin,
which runs in a worker to fetch hosts and groups from NetBox, a cloud, or a generator, or to group the
inventory's own hosts by their vars (`constructed`).

1. **Add source** in the inventory's **Dynamic sources** card. Give it a name and the plugin's YAML config;
   the **Examples** buttons fill in a starting point. Don't put tokens in the config (everyone who can see
   the inventory can read it): put them in an **environment variables** credential, pick it under
   **Credential**, and refer to them with `{{ lookup('env', 'NETBOX_TOKEN') }}`.
2. **Refresh now** runs every enabled source in a worker. The result is kept as a **snapshot**: the badge
   shows whether the last refresh worked, when, and how many hosts and groups it found, with any warnings
   (for example host names Ansible would misread, which are skipped).
3. **Hosts a run sees** lists the merged result (searchable, 100 hosts per page): which hosts came from a
   source, which from the inventory itself, their groups and vars. The inventory's own host vars win over
   a source's.

More about sources:

- **Refresh** sets a schedule (every 5 minutes to every day); "when something changes" refreshes after a
  source or the inventory's own hosts change. A refresh fails as a whole when any source fails, and runs
  keep using the last good snapshot. Admins can be notified (**Inventory refresh failed**).
- A run uses the snapshot current when it starts, and a run can't start until the first refresh worked.
- Turn a source off with its switch, **Edit** it, or **Delete** it (after a confirmation).
- Strings that come from a source are never templated by Ansible, so data in NetBox or a cloud API can't
  run code in your playbooks. Which plugins are allowed, and what a refresh may return, is described in
  the README's [Dynamic inventory sources](../../README.md#dynamic-inventory-sources-optional).
