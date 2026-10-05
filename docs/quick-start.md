# Quick start

This gets AnsiDeck running on your own machine and runs a first playbook, in about ten minutes. It uses
the development setup from the repository, which is meant for trying things out and for working on
AnsiDeck. To run it for real, follow [installing.md](installing.md) instead.

You need Git and Docker with Compose.

## 1. Start it

```sh
git clone https://github.com/HoneyBearTech/AnsiDeck.git
cd AnsiDeck
cp .env.example .env
docker compose up --build
```

The first start builds the images and takes a few minutes. When the log shows the backend answering
health checks, open <http://localhost:5173> and sign in as `admin` with the password from `ADMIN_PASSWORD`
in `.env` (`change-me` unless you edited it).

## 2. Add what a run needs

A run combines a **playbook** (what to do), an **inventory** (where), and a **credential** (the SSH key
AnsiDeck connects with). Everything lives in a project; a `Default` project exists already.

1. **Credentials → New Credential**: give it a name and paste a private key that can log in to your test
   host (or upload the key file). Passphrase-protected keys aren't supported yet.
2. **Inventories → New Inventory**: create `lab`, open it, and **Add Host** with the host's name or
   address. Put connection settings in the host's vars as JSON, for example
   `{"ansible_user": "deploy"}`.
3. **Playbooks → New Playbook**: name it `ping.yml` and paste:

   ```yaml
   - hosts: all
     gather_facts: false
     tasks:
       - name: Can we reach it?
         ansible.builtin.ping:
   ```

   Then **Save**.

No test host at hand? Use the inventory host `localhost` with the vars
`{"ansible_connection": "local"}`: the playbook then runs inside AnsiDeck's worker container, which is
enough to see a run work. You still have to pick a credential, any SSH key will do.

## 3. Run it

Go to **Runs → New Run**, pick the playbook, the inventory and the credential, tick **Check mode** to be
safe, and click **Trigger Run**. The run's page shows the output live as Ansible works, then a summary: how
many hosts were ok, changed, failed or unreachable, and how long it took.

## What next

- The [user guide](user-guide/README.md) explains every page, including git-synced playbooks, dynamic
  inventories, vault passwords, notifications and API keys for CI.
- [Security requirements](security.md) say what AnsiDeck protects and what it doesn't. Read them before
  you point it at hosts that matter.
- Stop the stack with `docker compose down` (add `-v` to delete its data too).
