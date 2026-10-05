# Playbooks and Galaxy

## Playbooks

**Playbooks** lists the project's playbooks. Operators and admins can:

- **New Playbook**: give it a name and type or paste the YAML, or **Upload YAML file** (the name defaults
  to the file's). It must be valid YAML: a playbook is checked when you save it.
- Open a playbook to edit and **Save** it, or **Delete** it from the list (after a confirmation). Run
  history stays.
- **Run** opens a new run (see [Runs](runs.md)).

The editor highlights YAML and numbers its lines; undo and redo work as usual (Ctrl+Z / Ctrl+Shift+Z,
⌘ on a Mac). Tab moves on to the next control rather than indenting, so the keyboard never gets stuck in
it; indent with spaces. The same editor shows inventory source configs and the Galaxy requirements.

### Checking a playbook

**Check** (operators and admins) runs [ansible-lint](https://docs.ansible.com/projects/lint/) on the
playbook in a worker and lists what it found: errors and warnings, each with its line, the rule (linked
to its explanation) and details. Findings in the playbook are also marked in the editor's margin and
underlined in the text; **Go to line** jumps there.

- It checks the text **as it is in the editor**, saved or not, and even if it isn't valid YAML yet (that
  is reported as an error). Saving never waits for a check, and nothing stops you from saving a playbook
  with findings.
- After you change the text, the results say they are for an earlier version: check again.
- A playbook **synced from git** is checked inside its repository at the current commit, with the
  repository's roles and its own ansible-lint configuration (`.ansible-lint`, `.yamllint`,
  `.ansible-lint-ignore`) if it has one; other playbooks use ansible-lint's default rules. Findings in
  the repository's roles or task files are listed with their file.
- Checks run offline: only collections and roles installed on the [Galaxy](#galaxy) page are available, so
  a module from anything else is reported as unknown. A repository's `requirements.yml` isn't installed.
- Each person has one check waiting at a time (a new one replaces it), a few run at once across all
  workers, and a check is stopped after 2 minutes; playbooks over 1 MiB can't be checked. Results are
  visible only to you and are deleted after an hour.

## Playbooks from git

A project admin can sync playbooks from a git repository instead, under **Git sources** on the Playbooks
page. Synced playbooks are read-only in AnsiDeck (change them in the repository), and each run executes
inside the repository at the commit that was current when it started, so roles, `group_vars` and other
files next to the playbook are there too.

1. **Add git source**:
   - **Repository URL**: `https://…` or an SSH address (`git@host:org/repo.git` or `ssh://…`).
   - **Branch**, an optional **Subdirectory**, and the **Playbook files** to list (patterns such as
     `*.yml, playbooks/*.yml`; only files that are playbooks appear).
   - **Authentication**: none for a public repository, a user name and **token** over HTTPS, or an **SSH
     deploy key** (one of the project's SSH credentials; add its public half to the repository as a
     read-only deploy key).
   - **Sync**: manually only, or every minute up to every hour. **Web URL** turns commits into links.
2. For SSH, **Test connection** shows the host keys the server presented: compare a fingerprint with the
   one your git host publishes and **Trust** it (or **Paste a known_hosts line instead**). Syncing waits
   until a host key is trusted.
3. **Sync now** (operators too) fetches the branch. The card shows the commit, how many playbooks it found,
   any that were removed upstream, warnings (for example a `requirements.yml` that isn't installed
   automatically) and sync errors.

Playbooks removed upstream stay listed (and can be deleted) but can't run. **Edit** changes a source;
**Delete** removes it with its synced playbooks, after a confirmation (run history stays). Remotes on
private addresses need the server's `GIT_ALLOWED_PRIVATE_HOSTS`; see the README's
[Playbooks from git](../../README.md#playbooks-from-git-optional).

## Galaxy

Global admins install roles and collections on the **Galaxy** page, for every project's runs.

1. Edit **requirements.yml** (Galaxy names, `https://` URLs and `git+https://` sources only) and **Save**.
2. Tick **I understand this runs third-party code** (and **Upgrade / reinstall** if wanted), then
   **Install**. The output shows live; **Install history** keeps past installs.

While an install waits or runs, no new run starts, and an install waits for running runs to finish.
Installed content is code that runs with your playbooks, with access to the secrets they use: install only
what you trust. **Installed** lists the collections and roles present.
