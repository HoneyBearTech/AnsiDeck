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

## Before you open a pull request

Run the same checks CI runs and make sure they pass. The backend tests need Postgres:
`docker compose up -d postgres` is enough. They create and drop their own `ansideck_test` database there; set
`TEST_DATABASE_URL` to use another server (its database name must end in `_test`).

Schema changes go through Alembic: edit `app/models.py`, then generate a migration with
`uv run alembic revision --autogenerate -m "..."`, review it, and commit it with the model change. A test fails
if the models and the migrations disagree.

```sh
# backend/
uv lock --check
uv run ruff check .
uv run ruff format --check .    # `uv run ruff format .` fixes formatting
uv run pytest --cov              # prints coverage; CI requires 80% branch coverage

# frontend/
npm run lint
npm run typecheck
npm run build
```

CI also enforces a floor of 80% branch coverage for the backend, audits dependencies for known
vulnerabilities, and runs CodeQL and Docker image builds. Pull requests that touch `backend/` are also
fuzzed for a minute per target: Atheris drives the Hypothesis properties in `backend/tests/test_properties.py`
through `backend/fuzz/fuzz_properties.py` (Linux x86_64 only; `uv sync --group fuzz`). If a fuzz job fails,
download its `crash-<target>` artifact and replay it with `uv run python fuzz/fuzz_properties.py <target> <file>`.

## Coding standards

Contributions must follow these style guides; CI enforces them, and a pull request that fails them can't be
merged.

- **Python** (`backend/`): [PEP 8](https://peps.python.org/pep-0008/) as enforced by
  [ruff](https://docs.astral.sh/ruff/) with the rule set in `backend/pyproject.toml`, and formatting by
  `ruff format` (line length 100). Write docstrings for modules and for functions whose purpose isn't
  obvious from their name, following [PEP 257](https://peps.python.org/pep-0257/). Use type hints.
- **TypeScript and React** (`frontend/`): the TypeScript compiler settings in `frontend/tsconfig*.json`
  and the [oxlint](https://oxc.rs/docs/guide/usage/linter) rules in the frontend's configuration. Follow the
  existing component patterns (Radix primitives in `src/components/ui/`, Tailwind tokens in `src/index.css`).
- **Exceptions** are rare: suppress a single finding on its own line (`# noqa: <rule>` or
  `// oxlint-disable-next-line <rule>`) with a short reason, never a whole file or rule without one.
- Beyond the tools, follow the style of the surrounding code rather than introducing a new one.

## Test policy

- **New functionality must come with automated tests.** When a pull request adds or changes major
  functionality, it must add tests for it to the automated test suites (`backend/tests/`, and the frontend
  tests once they exist), covering both the expected behaviour and the ways it should refuse input or
  access.
- **Bug fixes must come with a regression test** that fails without the fix, unless that is impractical,
  in which case the pull request says why.
- **Coverage must not drop below the floors CI enforces** (80% branch coverage for the backend).
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
