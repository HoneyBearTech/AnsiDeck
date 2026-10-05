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

3. **The encryption key**, `secrets/credential_encryption_key`, once (it doesn't change). Without it the
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

## From the SQLite era

Installations from before AnsiDeck moved to PostgreSQL kept everything in `/data/ansideck.db`. The backend
refuses to start while that file exists next to an empty database, and prints the one-time import
command. The [README](../README.md#upgrading-from-sqlite) describes the import and how to check it first.
