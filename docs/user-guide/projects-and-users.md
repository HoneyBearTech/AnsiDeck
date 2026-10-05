# Projects, users and sign-in

## Projects

**Projects** (global admins create, rename and delete them) separate who can see and change content.
Each project shows your role in it, and admins of a project can open its **Members** and **API keys**.

- A new installation has a `Default` project.
- Deleting a project asks first, and only works when it's empty (no playbooks, inventories, credentials
  and so on); its run history is deleted with it.
- Runs of different projects are kept apart on the workers (each run executes as a separate Linux user
  and can't read other runs' files), but they share the workers' network. Only give operator access to
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

- **New User**: a user name, an initial password (at least 12 characters), optionally an email address
  (needed for single sign-on, below), a role, and the project to add them to. A non-admin user only sees
  the projects they're a member of; the role picked here seeds that first membership. Pick **admin** to make
  a global admin.
- On each user: change the role, set the **Email**, **Reset password**, **Reset 2FA** (when they lost their
  authenticator and recovery codes), **Deactivate** / **Activate**, **Unlink SSO** and **Delete**. Changing
  the role, deactivating, or resetting a password or 2FA signs that user out immediately. Deleting asks
  first; deactivating is usually better, and run history keeps the user's name either way.
- You can't change your own role or deactivate yourself here; change your own password on **Account**.

## Signing in

### Password and two-factor login

Sign in with your user name and password. After five wrong passwords in five minutes the account is
locked for a while, and too many failures from one address lock that address; admins are notified.

Under **Account** you can change your password (at least 12 characters, not your user name; your other
sessions are signed out) and turn on **two-factor login**:

1. **Set up two-factor login**, and confirm with your current password.
2. Scan the QR code with an authenticator app (1Password, Google Authenticator, Aegis, …), or type the key
   shown under it, and enter the six-digit code.
3. Save the **recovery codes** (copy or download them). Each one signs you in once if you lose the
   authenticator; they aren't shown again.

From then on, a password sign-in asks for a code from the app (or a recovery code). **New recovery codes**
replaces the old ones; **Turn off** needs your password and a code. Two-factor login applies to password
sign-ins only: single sign-on relies on your provider's MFA.

If a global admin loses access, another admin can reset their two-factor login on **Users**, or on the
server: `docker compose exec backend python -m app.cli reset-totp <username>`.

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

## API keys for CI

A project admin creates API keys under **Projects → API keys**, so CI/CD can start runs and follow them
without a user account.

1. Enter a name (letters, digits, `.`, `_`, `-`), pick a preset and a lifetime (30 days, 90 days or a year),
   and **Create key**.
   - **trigger**: start runs and read their status and output, in this project only. It can never run as
     root or edit anything.
   - **read-only**: read run status and output.
2. Copy the key from the dialog: it's shown **once**. Send it as `Authorization: Bearer <key>`, over HTTPS.
3. The list shows each key's status, when it was last used, and when it expires. **Revoke** (after a
   confirmation) stops a key at once.

The README's [Triggering runs from CI](../../README.md#triggering-runs-from-ci) has `curl` examples for
starting runs (directly or from a [template](runs.md#run-templates)), polling, cancelling, and downloading
their output.
