# Verifying releases

Every AnsiDeck release is built and published by the
[`docker-publish.yml`](../.github/workflows/docker-publish.yml) workflow when a version tag is pushed. You
can check that what you run came from that workflow, unchanged:

- the **container images** are signed with [cosign](https://docs.sigstore.dev/) "keylessly": the signature
  is tied to the workflow's GitHub identity through [Sigstore](https://www.sigstore.dev/), so there is no
  long-lived signing key to steal, and every signature is recorded in the public Rekor transparency log;
- the images carry an **SBOM** (software bill of materials) and **SLSA provenance** (how and from which
  commit they were built) as attestations;
- each GitHub Release has a source archive, `images.txt` (the image digests) and `SHA256SUMS`, which is
  signed the same way (`SHA256SUMS.sigstore.json`);
- from v0.1.1 on, the release files also have **SLSA build provenance**: a signed attestation, stored by
  GitHub and attached to the release (`ansideck-<version>.intoto.jsonl`, the signed in-toto envelope, and
  `ansideck-<version>.provenance.sigstore.json`, the full Sigstore bundle), saying which workflow run
  built them from which commit;
- the **version tag** in git is signed with the maintainer's SSH key.

You need [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 2.0 or later. The
examples use v0.1.0.

## The images

```sh
for image in ansideck-backend ansideck-frontend; do
  cosign verify "ghcr.io/honeybeartech/${image}:0.1.0" \
    --certificate-identity-regexp '^https://github\.com/HoneyBearTech/AnsiDeck/\.github/workflows/docker-publish\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
done
```

cosign prints the verified signatures, including the commit and tag they were built from. A tag such as
`0.1.0` can be moved, a digest can't: for production, pin the digests from the release's `images.txt`
(after verifying it, below), for example `ghcr.io/honeybeartech/ansideck-backend@sha256:…`.

To see the SBOM and the provenance:

```sh
docker buildx imagetools inspect ghcr.io/honeybeartech/ansideck-backend:0.1.0 --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/honeybeartech/ansideck-backend:0.1.0 --format '{{ json .Provenance }}'
```

## The release files

Download `SHA256SUMS`, `SHA256SUMS.sigstore.json`, `images.txt` and the source archive from the
[release page](https://github.com/HoneyBearTech/AnsiDeck/releases), then:

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/HoneyBearTech/AnsiDeck/\.github/workflows/docker-publish\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS
```

The first command proves `SHA256SUMS` came from the release workflow; the second, that the archive and
`images.txt` match it.

## Build provenance (from v0.1.1)

With the [GitHub CLI](https://cli.github.com/), check that a downloaded release file was built by this
repository's release workflow:

```sh
gh attestation verify ansideck-0.1.1.tar.gz --repo HoneyBearTech/AnsiDeck \
  --signer-workflow HoneyBearTech/AnsiDeck/.github/workflows/docker-publish.yml
gh attestation verify images.txt --repo HoneyBearTech/AnsiDeck \
  --signer-workflow HoneyBearTech/AnsiDeck/.github/workflows/docker-publish.yml
```

It prints the verified attestation, including the commit and workflow run. To verify offline, add
`--bundle ansideck-0.1.1.provenance.sigstore.json`. Every file listed in `SHA256SUMS` is covered.

## The git tag

The maintainer signs version tags with an SSH key whose public half is in
[`.github/allowed_signers`](../.github/allowed_signers):

```sh
git clone https://github.com/HoneyBearTech/AnsiDeck.git && cd AnsiDeck
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers tag -v v0.1.0
```

It should print `Good "git" signature for 31805425+HoneyBearTech@users.noreply.github.com`. Check
`.github/allowed_signers` against the key published at <https://github.com/HoneyBearTech.keys> or in an
earlier release, rather than trusting the copy in the same checkout alone.

## If a check fails

Don't run that image or file. Re-download it; if the check still fails, report it privately as a security
issue ([SECURITY.md](../SECURITY.md)).
