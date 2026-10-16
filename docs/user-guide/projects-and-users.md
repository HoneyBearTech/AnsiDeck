# Projects, users and sign-in

## Projects

**Projects** (global admins create, rename and delete them) separate who can see and change content.
Each project shows your role in it, and admins of a project can open its **Members** and **API keys**.

- A new installation has a `Default` project.
- Deleting a project asks first, and only works when it's empty (no playbooks, inventories, credentials
  and so on); its run history is deleted with it.
- Runs of different projects are kept apart on the workers (each run executes as a separate Linux user
  and can't read other runs' files), but they share the workers' network (apart from the API and cloud
  metadata, which runs can't reach). Only give operator access to
  people you'd trust with your hosts.

### Members

A project admin manages the project's members under **Projects → Members**:

- **Add an existing user** by their user name, with a role: viewer, operator or admin (the help text under
  the form says what each can do). Users are created on the **Users** page first.
- Change a member's role with the selector next to them, or **Remove** them (after a confirmation); they
  lose access at once.
- A project admin can't change or remove their own membership (a global admin can).

## Users

Global admins manage accounts on the **Users** page.

- **New user**: a user name, an initial password (at least 12 characters), optionally an email address
  (needed for single sign-on, below), a role, and the project to add them to. A non-admin user only sees
  the projects they're a member of; the role picked here seeds that first membership. Pick **admin** to make
  a global admin.
- On each user: change the role, set the **Email**, **Reset password**, **Reset 2FA** (when they lost their
  authenticator app, passkeys and recovery codes: all of them are removed), **Deactivate** / **Activate**,
  **Unlink SSO** and **Delete**. Changing
  the role, deactivating, or resetting a password or 2FA signs that user out immediately. Deleting asks
  first; deactivating is usually better, and run history keeps the user's name either way.
- You can't change your own role or deactivate yourself here; change your own password on **Account**.

## Signing in

### Password and two-factor login

Sign in with your user name and password. After five wrong passwords in five minutes the account is
locked for a while, and too many failures from one address lock that address; admins are notified.

Under **Account** you can change your password (at least 12 characters, not your user name; your other
sessions are signed out) and turn on **two-factor login** with passkeys, an authenticator app, or both.

**Passkeys** confirm it's you with your device's own unlock: Touch ID or Face ID, Windows Hello, your
phone's screen lock, or a security key such as a YubiKey.

1. **Add a passkey**, enter your current password and a name for it (to tell your passkeys apart), and
   follow your browser's prompt.
2. If it's your first second factor, save the **recovery codes** (copy or download them). Each one signs
   you in once if you lose your passkeys and authenticator app; they aren't shown again.

You can add up to ten (a laptop, a phone and a spare security key, say), rename them, and see when each
was last used. A passkey marked **synced** is kept by your platform (iCloud Keychain, Google Password
Manager, a password manager) and works on your other devices too.

Passkeys work only at the address the server is set up for (`PUBLIC_URL`, which must be `https://`, or
`http://localhost` to try it out); the Account page says so when that isn't where you are.

**An authenticator app** (1Password, Google Authenticator, Aegis, …):

1. **Set up an authenticator app**, and confirm with your current password.
2. Scan the QR code, or type the key shown under it, and enter the six-digit code.
3. Save the recovery codes if it's your first second factor.

From then on, a password sign-in asks for one of them: **Use a passkey**, a code from the app, or a recovery
code. **New recovery codes** replaces the old ones. Turning a second factor off (**Turn off** for the app,
**Remove** for a passkey) needs your password and a current second factor: a code, a recovery code, or one
of your passkeys. Turning off the last one also removes your recovery codes. Two-factor login applies to
password sign-ins only: single sign-on relies on your provider's MFA.

If someone loses access, a global admin can reset their two-factor login on **Users**, or on the server:
`docker compose exec backend python -m app.cli reset-2fa <username>` (`reset-totp` still works).

#### Requiring two-factor login for admins

With `REQUIRE_ADMIN_2FA=true`, global admins and project admins who sign in with a password and have no
second factor see only a **Set up two-factor login** page until they add a passkey or an authenticator app
(or sign out); the API refuses everything else for that session, and the refusals are audited. While it is
on, an admin can't remove their last second factor. Single sign-on sessions and API keys are not affected.
Turn it on once the admins know it's coming: anyone it locks out can still set up a factor at their next
sign-in.

### Single sign-on

AnsiDeck can sign people in with an OpenID Connect provider (Keycloak, Entra ID, Google, Authentik, …) or
with GitHub, once the server is configured (see [Single sign-on](../../README.md#single-sign-on-optional)
in the README). The login page then shows **Sign in with …** buttons.

- Nobody is created automatically: an admin first creates the user and sets their **email** to an address
  the provider has verified. The first SSO sign-in links the account by that email; after that it is
  matched by the provider's stable id.
- Global admins can't use SSO unless the server sets `SSO_ALLOW_ADMIN=true`, so password login stays the
  way in if the provider has a problem.
- **Unlink SSO** on **Users** frees the account to link to a different identity.
- The server can limit GitHub sign-in to members of some GitHub organizations or teams; anyone else sees
  "Your GitHub account isn't in an organization or team allowed here".
- It can also give GitHub team members project roles. Those memberships show **via GitHub** under the
  project's members and follow the team at each GitHub sign-in (a password sign-in removes them until the
  next GitHub one). Changing such a member's role, or **Make manual**, turns it into an ordinary
  membership that sign-ins leave alone. Removing it only lasts until their next GitHub sign-in while their
  team still grants it.

## API keys for CI

A project admin creates API keys under **Projects → API keys**, so CI/CD can start runs and follow them
without a user account.

1. Enter a name (letters, digits, `.`, `_`, `-`), pick a preset and a lifetime (30 days, 90 days or a year),
   enter your current password, and **Create key**. (If you signed in with single sign-on in the last 15
   minutes, no password is needed; otherwise sign in again first.)
   - **trigger**: start runs and read their status and output, in this project only. It can never run as
     root or edit anything. Its runs' extra vars are templated by Ansible, though, so whoever holds it can
     run commands in a worker slot and on the project's hosts, with the run's SSH key, like an operator:
     keep it as safe as that.
   - **read-only**: read run status and output.
2. Copy the key from the dialog: it's shown **once**. Send it as `Authorization: Bearer <key>`, over HTTPS.
3. The list shows each key's status, when it was last used, and when it expires. **Revoke** (after a
   confirmation) stops a key at once.
4. **Rotate** replaces a key with a new one of the same name, preset, lifetime and limits, created by you (it
   asks for your password, like creating one). The old key stops working at once, so update the pipeline
   that uses it straight away.
5. **Limits** (or **Add limits** when creating one) narrows what a key can do, and can be changed later
   without a new key (every change is in the audit log):
   - **Allowed addresses**: addresses or CIDRs it may be used from, as AnsiDeck sees them: behind a reverse
     proxy, that proxy must be listed in `TRUSTED_PROXIES` (see [installing](../installing.md)), or every
     request seems to come from the proxy. Check **last used** on the key. From anywhere else the key is
     refused like a wrong one.
   - **Playbooks it may run** and **Inventories it may run against**: it can start runs (directly or from a
     template) of those only. A read-only key's reading isn't limited by these.

A revoked key's name can be used again. Keys revoked or expired more than `API_KEY_RETENTION_DAYS` ago
(90 by default; 0 keeps them) are deleted from the list; runs they started still show who started them, and
the audit log keeps each key's creation, rotation and revocation.

A key works only while the person who created it could create it again: it is **suspended** while they are
deactivated, no longer an admin of the project, or removed from it, and works again if that changes.
Deleting them stops their keys for good. The list says why a key is suspended, and every refused request is
in the audit log. When someone leaves, have a remaining admin create new keys for the pipelines that need
them.

The README's [Triggering runs from CI](../../README.md#triggering-runs-from-ci) has `curl` examples for
starting runs (directly or from a [template](runs.md#run-templates)), polling, cancelling, and downloading
their output.
