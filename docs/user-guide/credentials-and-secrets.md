# Credentials and secrets

Secrets are write-only in AnsiDeck: once saved, a key, password or token is never shown again, to anyone.
Operators can pick a project's credentials for runs; only project admins create and delete them.

## Credentials

**Credentials → New credential** stores one of two kinds:

- **SSH key**: the private key a run connects to its hosts with (and the deploy key a git source can
  use). Paste it, or upload the key file. Passphrase-protected keys aren't supported yet: use an
  unencrypted key, ideally one made for AnsiDeck and authorised only where it's needed.
- **Environment variables**: named values, such as `NETBOX_TOKEN`, given to dynamic inventory sources
  that use the credential (see [Inventories](inventories.md#dynamic-sources)). Names are upper-cased;
  add as many rows as you need. Only inventory refreshes receive them, never playbook runs, and their
  values are removed from refresh output.

Each credential is stored encrypted, or as a reference into a secret store (below). Deleting asks first;
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
- If the store is unreachable, runs that need it fail with the reason, and global admins can be notified
  (**Secret store unavailable**). Deleting the credential only deletes the reference; the secret stays in
  the store.
