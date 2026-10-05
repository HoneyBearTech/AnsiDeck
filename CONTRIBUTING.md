# Contributing to AnsiDeck

AnsiDeck is a personal project with a single maintainer. Contributions are welcome, but there is no
service-level agreement, and review may take a while. There are no tagged releases yet, so `main` is the
only supported line.

Please read the [Code of Conduct](CODE_OF_CONDUCT.md) and how the project is run ([GOVERNANCE.md](GOVERNANCE.md))
before you start.

## Reporting bugs and suggesting changes

- Use [GitHub Issues](https://github.com/HoneyBearTech/AnsiDeck/issues) for bugs, questions and feature ideas.
  For anything bigger than a small fix, please open an issue first so we can agree on the approach before you
  spend time on it.
- **Do not report security vulnerabilities in a public issue.** Follow [SECURITY.md](SECURITY.md) and use
  GitHub's private vulnerability reporting instead.

## Development setup

What you need:

- **Docker** with Compose (Engine 26 or later) for the whole stack, the images and the database;
- for working on the backend outside Docker: **Python 3.12** (3.12.11 or later) and
  [**uv**](https://docs.astral.sh/uv/), which installs every Python dependency from `backend/uv.lock`,
  including Ansible;
- for the frontend: **Node.js 24** and npm, which install every package from `frontend/package-lock.json`;
- `git` and `openssh-client`, which the backend calls for git sources and runs.

Dependencies come only from these lockfiles, the digest-pinned base images and the images' OS packages;
how they're chosen and kept up to date is in [docs/dependencies.md](docs/dependencies.md).

The whole stack, with hot reload (backend on `:8000`, frontend on `:5173`):

```sh
cp .env.example .env    # then edit as needed
docker compose up --build
```

Or run the pieces on their own:

```sh
# backend (Python, FastAPI, managed with uv); it needs the compose Postgres, on 127.0.0.1:5433
docker compose up -d postgres
cd backend
uv sync --all-groups
uv run fastapi dev app/main.py

# frontend (React + TypeScript, Vite)
cd frontend
npm install
npm run dev
```

### Building the release images

The production images are the `runtime` targets of the two Dockerfiles. They also copy the repository's
LICENSE, through a build context named `repo`:

```sh
docker build --target runtime --build-context repo=. -t ansideck-backend backend
docker build --target runtime --build-context repo=. -t ansideck-frontend frontend
```

`npm run build` (in `frontend/`) produces the static UI in `frontend/dist/`; two builds from the same
sources are byte-identical. The backend isn't compiled: the image installs it with `uv sync --frozen`.
Releases are built by `.github/workflows/docker-publish.yml`, see [docs/verifying-releases.md](docs/verifying-releases.md).

## When and how tests run

| Suite | What it tests | Runs locally with | Runs in CI |
| --- | --- | --- | --- |
| Backend (pytest, `backend/tests/`) | API, permissions, queue and workers, real `ansible-playbook` / `ansible-inventory` runs, migrations, security properties | `uv run pytest` (needs the compose Postgres) | every pull request and push to `main` (required) |
| Frontend (Vitest, `frontend/src/**/*.test.tsx`) | every page through the real routing and permission checks, against a fake API; accessibility (axe) | `npm test`, `npm run coverage` | every pull request and push to `main` (required) |
| Coverage floors | backend ≥ 80% branches, frontend ≥ 80% statements | as above | with the suites (required) |
| Fuzzing (Atheris, `backend/fuzz/`) | secret scrubbing, vault, inventory rendering | `uv run python fuzz/fuzz_properties.py <target>` | pull requests that touch `backend/` (1 min per target), weekly (10 min) |
| Static analysis | CodeQL security queries; ruff (incl. bandit) and oxlint | `uv run ruff check .`, `npm run lint` | every pull request, `main` and weekly (required) |
| Dependency checks | pip-audit, npm audit, dependency review | `uvx pip-audit …`, `npm audit` | every pull request (required) |
| Image smoke tests | the runtime images start, refuse insecure settings, serve security headers, run end-to-end checks | see `.github/workflows/docker-build.yml` | every pull request and push to `main` (required) |

A pull request can only merge when the required checks pass. A failing check's log in the pull request
names the failing test with its assertion; a coverage failure prints the uncovered lines.

## Before you open a pull request

Run the same checks CI runs and make sure they pass. The backend tests need Postgres:
`docker compose up -d postgres` is enough. They create and drop their own `ansideck_test` database there; set
`TEST_DATABASE_URL` to use another server (its database name must end in `_test`).

Schema changes go through Alembic: edit `app/models.py`, then generate a migration with
`uv run alembic revision --autogenerate -m "..."`, review it, and commit it with the model change. A test fails
if the models and the migrations disagree.

After changing a route or a request/response schema, regenerate the committed API description with
`uv run python scripts/export_openapi.py` (in `backend/`); a test fails when `docs/api/` is out of date.

```sh
# backend/
uv lock --check
uv run ruff check .
uv run ruff format --check .    # `uv run ruff format .` fixes formatting
uv run pytest --cov              # prints coverage; CI requires 80% branch coverage

# frontend/
npm run lint
npm run typecheck
npm test                         # `npm run coverage` adds coverage; CI requires 80% of statements
npm run build
```

Frontend tests live next to the code they test (`src/**/*.test.tsx`). Most render the whole app at a route
against an in-memory fake of the API (`src/test/render.tsx`, `src/test/fake-api.ts`), so a test drives
the page the way a person would: by labels, roles and visible text.

CI also enforces a floor of 80% branch coverage for the backend and 80% statement coverage for the
frontend, checks that the frontend build is reproducible, audits dependencies for known
vulnerabilities, and runs CodeQL and Docker image builds. Pull requests that touch `backend/` are also
fuzzed for a minute per target: Atheris drives the Hypothesis properties in `backend/tests/test_properties.py`
through `backend/fuzz/fuzz_properties.py` (Linux x86_64 only; `uv sync --group fuzz`). If a fuzz job fails,
download its `crash-<target>` artifact and replay it with `uv run python fuzz/fuzz_properties.py <target> <file>`.

## Coding standards

Contributions must follow these style guides; CI enforces them, and a pull request that fails them can't be
merged.

- **Python** (`backend/`): [PEP 8](https://peps.python.org/pep-0008/) as enforced by
  [ruff](https://docs.astral.sh/ruff/) with the rule set in `backend/pyproject.toml` (including its security
  rules), and formatting by `ruff format` (line length 100). The test suite turns Python warnings into
  errors. Write docstrings for modules and for functions whose purpose isn't
  obvious from their name, following [PEP 257](https://peps.python.org/pep-0257/). Use type hints.
- **TypeScript and React** (`frontend/`): TypeScript in strict mode with the extra checks in
  `frontend/tsconfig*.json`, and the [oxlint](https://oxc.rs/docs/guide/usage/linter) rules in
  `frontend/.oxlintrc.json` (warnings fail the lint). Follow the
  existing component patterns (Radix primitives in `src/components/ui/`, Tailwind tokens in `src/index.css`).
- **Accessibility**: give every control a label tied to it, keep one `<h1>` per page, and use the Radix-based
  components in `src/components/ui/` for dialogs, selects and switches. The axe tests in
  `src/test/a11y.test.tsx` must keep passing; see [docs/accessibility.md](docs/accessibility.md).
- **Exceptions** are rare: suppress a single finding on its own line (`# noqa: <rule>` or
  `// oxlint-disable-next-line <rule>`) with a short reason, never a whole file or rule without one.
- Beyond the tools, follow the style of the surrounding code rather than introducing a new one.

## Test policy

- **New functionality must come with automated tests.** When a pull request adds or changes major
  functionality, it must add tests for it to the automated test suites (`backend/tests/`, and `frontend/src/**/*.test.tsx`
  for the UI), covering both the expected behaviour and the ways it should refuse input or
  access.
- **Bug fixes must come with a regression test** that fails without the fix, unless that is impractical,
  in which case the pull request says why.
- **Coverage must not drop below the floors CI enforces** (80% branch coverage for the backend, 80% statement
  coverage for the frontend).
- Security-relevant changes should include a test that proves the protection works (for example a request
  from another project that must be refused).

## Developer Certificate of Origin

Every commit must be signed off to certify the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO): that you wrote the change, or otherwise have the right to submit it under the project's license.
Sign off by adding a `Signed-off-by` line with your name and e-mail address (a GitHub `noreply` address is
fine) to the commit message, which `git commit -s` does for you:

```text
Signed-off-by: Your Name <you@example.com>
```

A check on every pull request fails if a commit lacks the sign-off. To fix it, amend or rebase with
`--signoff` (for example `git rebase --signoff main`) and force-push your branch.

## Pull requests

- `main` is protected: changes land only through a pull request, and the required CI checks must pass. Pull
  requests are squash-merged.
- Keep each pull request focused on one change, and describe what it does and why.
- Add or update tests for behaviour changes, and update `README.md` or `.env.example` if you change
  configuration or user-visible behaviour.
- Follow the [coding standards](#coding-standards) and the [test policy](#test-policy), and sign off your
  commits ([DCO](#developer-certificate-of-origin)).
- Never commit secrets, private keys, vault passwords or `.env` files. Secret scanning and push protection are
  enabled on the repository.
- AnsiDeck holds SSH keys and runs automation against real infrastructure, so treat changes to
  authentication, credentials, secret handling or how runs are executed with extra care, and call them out in
  the pull request description.

## License

By contributing, you agree that your contribution is licensed under the project's [MIT License](LICENSE).
