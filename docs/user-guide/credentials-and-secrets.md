# Credentials and secrets

Secrets are write-only in AnsiDeck: once saved, a key, password or token is never shown again, to anyone.
Operators can pick a project's credentials for runs; only project admins create and delete them.

## Credentials

**Credentials → New credential** stores one of these kinds:

- **SSH key**: the private key a run connects to its hosts with (and the deploy key a git source can
  use). Paste it, or upload the key file. Passphrase-protected keys aren't supported yet: use an
  unencrypted key, ideally one made for AnsiDeck and authorised only where it's needed.
- **Environment variables**: named values, such as `NETBOX_TOKEN` or `AWS_ACCESS_KEY_ID` and
  `AWS_SECRET_ACCESS_KEY`, given to the dynamic inventory sources that use the credential (see
  [Inventories](inventories.md#dynamic-sources)) and to the runs started with it (**Environment
  credentials** on New run, for cloud modules). Names are upper-cased; add as many rows as you need.
  Names that change how ansible, Python, ssh, sudo or the worker behave (`ANSIBLE_*`, `PYTHON*`, `SSH_*`,
  `SUDO_*`, `PATH`, proxies, CA bundles and the like) are refused. Their values are removed from refresh
  and run output; a playbook can still read them, like any secret it is given.
- **SSH certificate (from OpenBao)**: offered only when the server's secret store has an SSH engine set
  up for it (see the README's [SSH certificates](../../README.md#ssh-certificates-optional)). It stores no
  key: each run gets a new key and a certificate the store signs for the run's timeout plus 5 minutes.
  Enter the **role** (its name in the store starts with the prefix shown, so a project only signs with its
  own roles) and the **principals**, the users the certificate may log in as; the inventory's
  `ansible_user` must be one of them. AnsiDeck signs a throwaway key once to check the role, and **Test**
  does it again (it shows the test certificate's serial and the CA's fingerprint). Runs can use it; git
  sources can't (a deploy key stays a key). Targets log one refused attempt with the bare key before they
  accept the certificate, and connections through paramiko can't use it.

Each SSH key or environment credential is stored encrypted, or as a reference into a secret store (below). Deleting asks first;
the secret is then gone from AnsiDeck for good. A credential that a git source or an inventory source
uses can't be deleted (the page says which); runs still queued with a deleted credential fail with that
reason.

## Vault passwords

Playbooks and extra variables can contain values encrypted with [Ansible
Vault](https://docs.ansible.com/ansible/latest/vault_guide/index.html). **Vault → New vault password**
stores the password that decrypts them; pick it when you start a run.

The **Vault** page also has two tools, for anyone allowed to use them:

- **Encrypt a value** (operators and admins): pick a vault password, optionally a variable name, and the
  value. You get a block to paste into playbook YAML and a string for a run's extra-vars JSON. **Copy**
  copies either.
- **Decrypt a value** (admins): paste a `$ANSIBLE_VAULT;…` envelope or a whole `name: !vault |` block. The
  plaintext is shown only on this page.

Deleting a vault password asks first. Values encrypted with it can then only be decrypted with your own
copy of the password.

## Keeping secrets in OpenBao or HashiCorp Vault

When the server is connected to a secret store (see the README's
[Secret store](../../README.md#secret-store-optional-openbao-or-hashicorp-vault)), the create dialogs offer
**Stored in AnsiDeck (encrypted)** or **In OpenBao** (or whatever the store is called):

- Enter the **path** of a KV v2 secret under the project's own subtree (shown as a prefix), and for an SSH
  key or vault password the **key** in that secret. For environment variables, every key in the secret
  becomes a variable.
- AnsiDeck reads the value once to check it, and again whenever a run or refresh needs it; it never stores
  it. Rotate it in the store, and the next run uses the new version.
- **Test** on a stored reference checks that AnsiDeck can read it now (it never shows the value).
- **Edit reference** points it at another path or key (an environment credential: another secret).
  AnsiDeck reads the new one once to check it before saving; queued runs use it when they start. The audit
  log records the old and new locations and the version read.
- A run's page lists which version of each reference its job read, so a change in the store can be traced
  to the runs that used it (the locations only for people who may see the project's secrets).
- If the store is unreachable, runs that need it fail with the reason, and global admins can be notified
  (**Secret store unavailable**). Deleting the credential only deletes the reference; the secret stays in
  the store.
