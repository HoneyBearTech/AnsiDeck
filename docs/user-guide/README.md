# User guide

AnsiDeck runs Ansible playbooks against your hosts from a web UI, keeps the output, and controls who can
do what. This guide walks through each page. If you haven't used AnsiDeck yet, start with the
[quick start](../quick-start.md).

> [!WARNING]
> Runs change real systems, and deletes can't be undone. See the warning in the
> [documentation index](../README.md).

## The building blocks

- **Projects** separate content and access: each playbook, inventory, credential, vault password, git
  source and run belongs to one project, and people get a role per project.
  → [Projects, users and sign-in](projects-and-users.md)
- **Credentials** are the SSH keys AnsiDeck connects with, or environment variables for inventory plugins;
  **vault passwords** decrypt Ansible Vault values. Stored encrypted, or kept in OpenBao / Vault.
  → [Credentials and secrets](credentials-and-secrets.md)
- **Inventories** list the hosts and groups to run against, typed in or fetched from a source such as
  NetBox. → [Inventories](inventories.md)
- **Playbooks** say what to do: pasted, imported, or synced from a git repository.
  → [Playbooks and Galaxy](playbooks.md)
- A **run** puts these together: one playbook, against one inventory (or a group of it), with one
  credential. → [Runs](runs.md)
- **Notifications** tell you when runs fail and when something needs an admin's attention.
  → [Notifications](notifications.md)
- **Workers**, the **audit log** and **metrics** are for administrators. → [Administration](administration.md)

## Roles at a glance

| | Viewer | Operator | Project admin | Global admin |
| --- | :-: | :-: | :-: | :-: |
| See playbooks, inventories, runs and their output | ✓ | ✓ | ✓ | ✓ |
| Edit playbooks and inventories, start and cancel runs, encrypt vault values | | ✓ | ✓ | ✓ |
| Manage credentials, vault passwords, git and inventory sources, members, API keys, project notifications; decrypt vault values; run as root | | | ✓ | ✓ |
| Manage users and projects, Galaxy installs, global notifications; see the audit log and workers | | | | ✓ |

Viewer, operator and project admin are roles **in a project**: someone can be an operator in one project and
a viewer in another. Global admins have every permission in every project.

## The header

The header's links lead to each page; pages you can't use are hidden or say "Not permitted". The project
switcher picks the project you work in: lists show its content, and what you create goes into it. Global
admins can also pick **All projects**. Click your user name for your **Account** (password and two-factor
login), and **Log out** to end the session in this browser.
