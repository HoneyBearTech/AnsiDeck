# Runs

> [!WARNING]
> A run executes the playbook on real hosts. What it changes stays changed, even if you cancel it. Use
> **check mode** and a narrow **limit** first.

## Starting a run

**Runs → New Run** (operators and admins). Pick:

- **Playbook**: synced playbooks show their git source; playbooks removed upstream aren't offered.
- **Inventory**, and a **Target**: all hosts, or one group (groups from dynamic sources are marked).
  For an inventory with dynamic sources, the form says how fresh its snapshot is, or that it needs a first
  refresh.
- **Credential**: the SSH key to connect with.
- **Vault password** (optional): needed if the playbook or extra vars contain vault-encrypted values.

Only the playbook's project's inventories, credentials and vault passwords are offered: a run lives in one
project. Optionally:

- **Limit**: an Ansible host pattern that narrows the run further (`web1`, `webservers[0]`, `!db*`).
- **Timeout** (minutes): the run is stopped as "timed out" after running this long (2 hours by default, at
  most 24; time spent queued doesn't count).
- **Check mode**: a dry run that reports changes without making them. **Diff mode**: show what changes in
  files and templates.
- **Extra vars (JSON)**: variables for this run, such as `{"release": "1.2"}`. Values whose names look
  secret (`password`, `token`, `key`, …) are masked on the run page and in the output.
- **Run as admin (become root)** (admins only): escalates privileges on the hosts, after you tick the
  confirmation.

**Trigger Run** queues it and opens its page.

## Following a run

The run's page shows the playbook, inventory and target, who started it and with which credential and
options, the git commit for synced playbooks, and the output **live** as Ansible works. If the connection
drops, it reconnects and continues where it left off. When the run ends: its status, how many hosts were
ok, changed, failed or unreachable, how long it waited and ran, and Ansible's exit code.

Statuses: **queued**, **running**, **success**, **failed**, **cancelled** and **timed out**. A note under
the title says why when it isn't Ansible's own result (a lost worker, a timeout, a cancel).

## The queue

Runs wait in a queue until a worker slot is free. A queued run's page says what it waits for: a free
worker, the run ahead of it on the same inventory, a Galaxy install, or no worker being online at all.

- Runs against the same inventory go one at a time, in the order they were started.
- While a Galaxy install waits or runs, no new run starts.
- If a worker disappears mid-run, the run is marked failed ("worker lost") about a minute later.

## Cancelling

**Cancel run** (anyone who may start runs in the project) asks first. A queued run never starts; a running
one is stopped within seconds, and tasks it already completed on the hosts are not undone.

## History

**Runs** lists the project's runs, newest first, with their target, who started them, the commit, the
options used and the status. Runs keep the names of the playbook, inventory and credential they used, so
the history stays readable after those are deleted.
