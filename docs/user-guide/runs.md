# Runs

> [!WARNING]
> A run executes the playbook on real hosts. What it changes stays changed, even if you cancel it. Use
> **check mode** and a narrow **limit** first.

## Starting a run

**Runs → New run** (operators and admins). Pick:

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
  confirmation. Runs started by someone without this permission (operators, API keys) never become
  another user: `become: true` in the playbook or the inventory has no effect, and `ansible_become` extra
  vars are refused. A task that runs `sudo` itself is limited only by what the SSH user may do on the
  host, so don't give the keys operators use more sudo rights than they need.

**Start run** queues it and opens its page. **Save as template** (for people who may edit content)
saves the form as a [run template](#run-templates) instead.

## Following a run

The run's page shows the playbook, inventory and target, who started it and with which credential and
options, the git commit for synced playbooks, and the output **live** as Ansible works, coloured as on the
command line (ok green, changed yellow, failed red, skipped blue; the recap per host by its outcome). If the
connection drops, it reconnects and continues where it left off. When the run ends: its status, how many hosts were
ok, changed, failed or unreachable, how long it waited and ran, and Ansible's exit code.

Statuses: **queued**, **running**, **success**, **failed**, **cancelled** and **timed out**. A note under
the title says why when it isn't Ansible's own result (a lost worker, a timeout, a cancel).

**Download** saves the output as a file: **text** (what the page shows, without colours) or **JSON lines**
(Ansible's events, one JSON object per line, for scripts). For a run that is still going, the file holds
what it has produced so far. Secret values known to AnsiDeck are removed from the output before it's stored,
so they aren't in the download either. Viewers can download too.

## The queue

Runs wait in a queue until a worker slot is free. A queued run's page says what it waits for: a free
worker, the run ahead of it on the same inventory, a Galaxy install, or no worker being online at all.

- Runs against the same inventory go one at a time, in the order they were started.
- While a Galaxy install waits or runs, no new run starts.
- If a worker disappears mid-run, the run is marked failed ("worker lost") about a minute later.

## Cancelling

**Cancel run** (anyone who may start runs in the project) asks first. A queued run never starts; a running
one is stopped within seconds, and tasks it already completed on the hosts are not undone.

## Running it again

Two buttons on a run's page, for anyone who may start runs in its project:

- **Run again** starts the same run at once, after a confirmation that says what it runs (and whether as
  root): the same playbook, inventory and target, credential, vault password, options and extra vars. The
  playbook and inventory are used as they are **now** (a synced playbook at its source's current commit),
  not as they were. Running as root still needs the permission to.
- **Edit and run** opens **New run** with the run's settings filled in, to change something first.
  Extra vars whose names look secret show `[REDACTED]` there: type their values again before triggering
  (**Run again** keeps them without showing them).

If something the run used has since been deleted, **Run again** is disabled and says what; **Edit and run**
lets you pick a replacement.

## Run templates

A template is a saved run: playbook, inventory and target, credential, vault password, options and extra
vars, under a name. **Templates** lists the project's templates; everyone in the project can see them.

- **Save one** from **New run** with **Save as template** (operators and admins). Only people who may run
  as root can save a template that does.
- **Run** starts it, after showing what it runs. The **limit** and **check mode** can be changed for that
  run only, for example to try it on one host first. Running a template that runs as root needs the
  permission to.
- **Edit** opens it in the **New run** form: change what you need, then **Update template** (or trigger a
  run from the changed form). Extra vars that show `[REDACTED]` keep their stored value if you leave them as
  they are.
- **Delete** (after a confirmation) removes the template; runs started from it are kept.

If a playbook, inventory, credential or vault password a template uses is deleted, the template says so and
can't run until it's edited. A CI/CD key can run a project's templates too; see the README's
[Triggering runs from CI](../../README.md#triggering-runs-from-ci).

## History

**Runs** lists the project's runs, newest first, with their number, target, who started them and when,
how long they took, how many hosts they reached (and how many failed), the commit, the options used and
the status. Runs keep the names of the playbook, inventory and credential they used, so
the history stays readable after those are deleted.
