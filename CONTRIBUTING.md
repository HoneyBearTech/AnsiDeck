# Contributing to AnsiDeck

AnsiDeck is a personal project with a single maintainer. Contributions are welcome, but there is no
service-level agreement, and review may take a while. There are no tagged releases yet, so `main` is the
only supported line.

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

## Pull requests

- `main` is protected: changes land only through a pull request, and the required CI checks must pass. Pull
  requests are squash-merged.
- Keep each pull request focused on one change, and describe what it does and why.
- Add or update tests for behaviour changes, and update `README.md` or `.env.example` if you change
  configuration or user-visible behaviour.
- Follow the style of the surrounding code rather than introducing a new one.
- Never commit secrets, private keys, vault passwords or `.env` files. Secret scanning and push protection are
  enabled on the repository.
- AnsiDeck holds SSH keys and runs automation against real infrastructure, so treat changes to
  authentication, credentials, secret handling or how runs are executed with extra care, and call them out in
  the pull request description.

## License

By contributing, you agree that your contribution is licensed under the project's [MIT License](LICENSE).
