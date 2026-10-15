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

Keep secrets out of host vars: use a credential or a vault password instead. Viewers see host vars with
secret-looking values (passwords, tokens, keys, vault-encrypted text) masked; operators and admins see
them as stored.

A run sees the inventory's **whole group tree**, so a play with `hosts: web` runs on the `web` group, and
picking a group as a run's target narrows the run to that group's hosts. A run uses the inventory as it was
when the run was started: edits made while it waits in the queue don't change it.

## SSH host keys

A run checks that each host is the machine it talked to before: ssh compares the key the host presents
with the one the inventory trusts, and refuses the host if they differ. The **SSH host keys** card on an
inventory's page shows how runs treat host keys (its **Mode**), each host without a trusted key, and the
keys.

- **Learn new hosts** (new inventories): a host's key is learned on its first run and trusted from then
  on. A run fails for a host whose key changed. Learned keys show as **unconfirmed**.
- **Strict: confirmed keys only**: only keys a project admin pasted or confirmed are trusted; a run fails
  for a host without one. Use it when a host must never be trusted on first contact.
- **Off: not checked**: runs talk to whatever answers at a host's address. Inventories created before
  AnsiDeck checked host keys start here, with a "host keys not checked" badge; switch them to **Learn new
  hosts** once you're ready.

Project admins manage the keys:

- **Scan host keys** asks every host whose address is known for its SSH keys, from a worker (where runs
  connect from; add jump hosts by name). The result lists each key with whether it is new, matches the key a
  run learned, is already trusted, or **differs from the trusted key**. Tick the keys to trust and **Trust
  selected**; **Select the learned keys that match** confirms learned keys the hosts still present. Compare a
  fingerprint with the host's own before trusting it: a scan shows what answered, not who. Hosts that don't
  answer are listed. Scans are kept for an hour.
- **Paste known_hosts** trusts keys from known_hosts lines, for example the output of
  `ssh-keyscan -p 2222 10.0.0.5` run from a machine you trust, or a host's
  `/etc/ssh/ssh_host_ed25519_key.pub` with its name put in front. **Preview** shows which keys are new,
  which replace a trusted key (with the old fingerprint), and which lines can't be used (hashed names,
  wildcards and `@cert-authority` lines). A key replaces the one of the same type for the same name.
- **Confirm learned** confirms every unconfirmed key, so strict runs trust them too. Compare the
  fingerprints with the hosts' own first if it matters.
- **Remove** forgets a key: in **Learn new hosts** mode the host's next run learns whatever key it is
  shown, in strict mode its runs fail until a key is trusted.

Keys are kept by the name ssh looks a host up by: its `ansible_host` (or its host name) in lower case, with
the port in brackets when it isn't 22 (`[10.0.0.5]:2222`). A host whose address is set by a template, or
only in a git repository's `group_vars`, can't be matched before a run ("address unknown"); keys its runs
learn aren't kept, so paste its key instead. Jump hosts (ProxyJump) are checked too: paste their keys
under the name you reach them by (a jump host's own key is never kept from what a run learns, and when
ssh refuses one, the run only shows "Connection closed" for the host behind it). Hosts that don't connect with ssh (`local`, `winrm`, `network_cli`) are
listed as "not ssh" and aren't checked.

Inventory and playbook variables can't turn the checks off (`ansible_host_key_checking`, or
`-o StrictHostKeyChecking=no` in `ansible_ssh_common_args`): AnsiDeck's ssh options come first. Put other
ssh options in `ansible_ssh_common_args`; `ansible_ssh_args` is AnsiDeck's on these inventories. When a run
fails on a host key, see [Runs](runs.md#when-ssh-refuses-a-host-key).

## Network

By default a run may connect anywhere except AnsiDeck's own API and cloud metadata services. Under
**Network** on an inventory's page, a project admin can set **Runs may reach** to **Only its hosts**. Its
runs may then reach only:

- its hosts' addresses, on any port: the hosts of the run's target group (all of them, whatever **Limit**
  says, since `delegate_to` often reaches hosts outside the limit), at the address each one's connection
  uses (`ansible_host`, `ansible_ssh_host`, `ansible_winrm_host`, ...; extra vars count);
- the first jump host each one names (`-J` or `ProxyJump` in `ansible_ssh_common_args`,
  `ansible_ssh_extra_args` or `ansible_ssh_args`), on its ssh port. Hosts behind a jump host are reached
  through it and needn't resolve on the worker;
- the **extra entries**: one per line, an address, a network (CIDR) or a host name, then ports such as `443`,
  `80,443` or `8000-8100` (any port without), then `#` and a note. Use them for what a playbook reaches that
  isn't in the inventory: package mirrors, `delegate_to` or `add_host` targets, a `ProxyCommand`'s proxy;
- DNS.

Everything else (TCP, UDP and ping) is refused at once, and the run's page lists what was refused. AnsiDeck's
API and cloud metadata stay blocked even if listed. The setting applies to runs that start from then on,
queued ones included.

The worker looks the names up just before the run starts, as the run would, and the run's page lists what
they resolved to. A run doesn't start when its limits can't be known in advance: a host whose address is
set by a template, or that connects with a plugin AnsiDeck can't read (such as `community.docker.docker`;
the panel marks these "address unknown"), or a name that doesn't resolve. Names whose addresses rotate (a
service behind a CDN) may resolve differently a moment later: list their networks instead. A
`ProxyCommand`, ssh arguments AnsiDeck can't read and a repository's own `group_vars`, `host_vars` and
`ansible.cfg` aren't read: connections they make are refused unless their targets are extra entries.

Restricted runs need a worker of this release with its egress filter on (Linux 5.6 or later); the Workers
page marks a worker whose check failed "no network allowlists", and restricted runs wait for another.

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
inventory's own hosts by their vars (`constructed`). A source reads the inventory's own host vars as
plain text: a `{{ ... }}` in one is not evaluated during a refresh (it still is in a run).

1. **Add source** in the inventory's **Dynamic sources** card. Give it a name and the plugin's YAML config;
   the **Examples** buttons fill in a starting point. Don't put tokens in the config (everyone who can see
   the inventory can read it): put them in an **environment variables** credential, pick it under
   **Credential**, and refer to them with `{{ lookup('env', 'NETBOX_TOKEN') }}`. The AWS and Proxmox plugins
   read their credentials from the environment by themselves (`AWS_ACCESS_KEY_ID` and
   `AWS_SECRET_ACCESS_KEY`; `PROXMOX_TOKEN_ID` and `PROXMOX_TOKEN_SECRET`), so the credential is all they need.
2. **Refresh now** runs every enabled source in a worker, each on its own. The result is kept as a
   **snapshot**: the badge shows whether the last refresh worked, when, and how many hosts and groups it
   found, with any warnings (for example host names Ansible would misread, which are skipped). Each source
   says what it found last, or why it failed.
3. **Hosts a run sees** lists the merged result (searchable, 100 hosts per page): which hosts came from a
   source, which from the inventory itself, their groups and vars. The inventory's own host vars win over
   a source's.

More about sources:

- **Sources refresh** sets the inventory's schedule (every 5 minutes to every day, or "when something
  changes"), and each source can have its own in its dialog (**Refresh**: the inventory's, or another
  interval). A scheduled refresh runs only the sources that are due; the others contribute what they found
  last, so a slow or rate-limited API can be asked less often than the rest. Each source shows its schedule
  and when it runs next, and has its own **Refresh** button. Adding or editing a source runs just that source;
  turning one off or deleting it, and editing the inventory's own hosts or groups, only combine again (no
  source runs); **Refresh now** runs every source. `constructed` sources are applied again in every refresh. When a source fails, the other sources' hosts are still
  updated and the failed source keeps what it found last; the refresh counts as failed and names the source.
  Admins can be notified (**Inventory refresh failed**); the all-clear comes once every source works again.
- A run uses the snapshot current when it starts, and a run can't start until the first refresh worked,
  unless it refreshes the sources first: tick that on **New run** (or in a template, or send
  `"refresh_first": true` with the API), or switch on **Refresh before every run** next to the schedule to
  make it the default. Such a run waits for its own refresh and fails if the refresh does.
- **Inventory file from git** (in **Add source**) reads an INI or YAML inventory file, or a directory of
  them, from a git source of the project (see [Playbooks](playbooks.md)), with the `group_vars/` and
  `host_vars/` beside it. It is read from the git source's current commit at each refresh, and a sync that
  changes those files refreshes it (it defaults to the inventory's schedule too). Only YAML and INI are
  read: a plugin config or a script in the repository doesn't run, and the repository's `ansible.cfg` isn't
  used. If a commit removes the file, the source fails (marked **missing upstream**) and keeps what it found
  last; delete the source to drop its hosts. A git source that inventory sources read from can't be deleted.
- Turn a source off with its switch, **Edit** it, or **Delete** it (after a confirmation).
- A source can say where and as whom to connect to a host, but not how: of Ansible's own variables it may
  only set `ansible_host`, `ansible_port`, `ansible_user` (and their `ansible_ssh_` forms),
  `ansible_network_os`, and `ansible_connection` as `ssh`, `network_cli`, `netconf`, `httpapi`, `winrm` or
  `psrp`. Any other `ansible_*` variable from a source is dropped, with a refresh warning naming it; set
  those on the inventory's own hosts or in the playbook instead.
- Strings that come from a source are never templated by Ansible, so data in NetBox or a cloud API can't
  run code in your playbooks. Which plugins are allowed, and what a refresh may return, is described in
  the README's [Dynamic inventory sources](../../README.md#dynamic-inventory-sources-optional).
