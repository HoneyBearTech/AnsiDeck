# Upgrading, backups and restores

This assumes the production setup from [installing.md](installing.md) (`deploy/compose.yaml` in
`/opt/ansideck`). With the development stack, the same commands work with its service and volume names.

## Back up

A complete backup has three parts. Take them together, and keep them apart from the AnsiDeck host.

1. **The database** (users, projects, inventories, credentials in encrypted form, run history):

   ```sh
   cd /opt/ansideck
   sudo docker compose exec -T postgres pg_dump -U ansideck -Fc ansideck > ansideck-$(date +%F).dump
   ```

2. **The data volume** (playbook files, run output, git snapshots, Galaxy content):

   ```sh
   sudo docker run --rm -v ansideck_backend-data:/data:ro -v "$PWD":/backup busybox \
     tar czf /backup/ansideck-data-$(date +%F).tgz -C /data .
   ```

3. **The encryption key**, `secrets/credential_encryption_key`, once (and again if you
   [change it](#changing-the-encryption-key)). Without it the
   stored credentials, vault passwords, tokens and two-factor secrets in a database backup can't be
   decrypted. Store it separately from the backups: whoever has both can read every stored secret.

The other files in `secrets/` and `.env` are easy to recreate, but backing them up saves time.

## Restore

Restore into the same version that made the backup, then upgrade if you need to.

```sh
cd /opt/ansideck
sudo docker compose stop backend worker frontend
sudo docker compose exec -T postgres pg_restore -U ansideck -d ansideck --clean --if-exists --no-owner \
  < ansideck-2026-10-05.dump
sudo docker run --rm -v ansideck_backend-data:/data -v "$PWD":/backup busybox \
  sh -c 'rm -rf /data/* && tar xzf /backup/ansideck-data-2026-10-05.tgz -C /data'
sudo docker compose start backend worker frontend
```

On a new host, put back `secrets/` (with the same `credential_encryption_key`) and `.env` first, start
only the database (`docker compose up -d postgres`), restore as above, then `docker compose up -d`.

## Upgrade

1. Read the [changelog](../CHANGELOG.md) for every version between yours and the new one, especially its
   "Upgrading" notes. Before 1.0, a minor version can need manual steps.
2. [Verify](verifying-releases.md) the new images, and [back up](#back-up).
3. Set `ANSIDECK_VERSION` in `.env` to the new version, and replace `compose.yaml` with the one from the
   new release if the notes say it changed.
4. Pull and restart:

   ```sh
   sudo docker compose pull
   sudo docker compose up -d --wait
   ```

   The new API migrates the database when it starts. Runs that were still queued or running are marked
   failed with the reason, so check the **Runs** page afterwards. Workers start once the API is healthy.

Downgrades aren't supported: migrations only go forward. To go back, restore the backup you took before
upgrading, with the old `ANSIDECK_VERSION`.

## Changing the encryption key

Change `credential_encryption_key` when it may have leaked, or if your installation still uses the example
key from the repository's `.env.example` (production refuses to start with that one first). The file can
list several keys, separated by commas: the first encrypts, and all of them decrypt.

1. [Back up](#back-up), including the current key.
2. Generate a new key and put it first, keeping the old one after a comma:

   ```sh
   new=$(python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")
   printf '%s,%s\n' "$new" "$(cat secrets/credential_encryption_key)" \
     | sudo tee secrets/credential_encryption_key.new >/dev/null
   sudo chmod 444 secrets/credential_encryption_key.new
   sudo mv secrets/credential_encryption_key.new secrets/credential_encryption_key
   sudo docker compose up -d --wait --force-recreate backend
   ```

   The API now writes new secrets with the new key and still reads the old ones (its log warns that an old
   key is listed).
3. Re-encrypt everything stored under the new key:

   ```sh
   sudo docker compose exec backend python -m app.cli reencrypt-secrets
   ```

   It changes nothing if any stored value can't be decrypted with the listed keys, and says which.
4. Remove the old key, recreate the backend again, and back the new key up separately as before:

   ```sh
   cut -d, -f1 secrets/credential_encryption_key | sudo tee secrets/credential_encryption_key.new >/dev/null
   sudo chmod 444 secrets/credential_encryption_key.new
   sudo mv secrets/credential_encryption_key.new secrets/credential_encryption_key
   sudo docker compose up -d --wait --force-recreate backend
   ```

## From the SQLite era

Installations from before AnsiDeck moved to PostgreSQL kept everything in `/data/ansideck.db`. The backend
refuses to start while that file exists next to an empty database, and prints the one-time import
command. The [README](../README.md#upgrading-from-sqlite) describes the import and how to check it first.
