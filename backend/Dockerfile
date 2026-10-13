# uv, pinned by version and digest (a stage of its own so Dependabot updates it; keep
# .github/workflows/ci.yml and fuzz.yml on the same version).
FROM ghcr.io/astral-sh/uv:0.12.24@sha256:3af4716e991d6956a41e573eab705d0ee08500cd829ed30293eb8472f372c65a AS uv

FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS base
COPY --from=uv /uv /uvx /bin/
WORKDIR /app
RUN mkdir -p /data
# Ansible's default connection plugin shells out to the system `ssh` binary —
# not present in the slim base image, and not something this app should rely
# on the host to provide. git is for ansible-galaxy installs from git sources.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client git \
    && rm -rf /var/lib/apt/lists/*
# One user per worker slot (app.run_isolation): the worker runs each slot's playbooks as
# ansideck-run<n>, uid/gid 20000+n, with no capabilities. ssh and ansible refuse to run as a
# uid without a passwd entry. The worker creates the homes (on its /tmp tmpfs) at startup.
RUN for n in $(seq 0 63); do \
      groupadd --gid $((20000 + n)) "ansideck-run$n" \
      && useradd --uid $((20000 + n)) --gid $((20000 + n)) --no-create-home \
         --home-dir "/tmp/ansideck-home/run$n" --shell /usr/sbin/nologin "ansideck-run$n"; \
    done

FROM base AS deps
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

FROM deps AS dev
COPY . .
RUN uv sync --frozen
CMD ["uv", "run", "fastapi", "dev", "app/main.py", "--host", "0.0.0.0", "--port", "8000"]

FROM deps AS build
COPY . .
RUN uv sync --frozen --no-dev

FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS runtime
# upgrade: security fixes published since the pinned base image (the release scan fails on any
# fixable HIGH or CRITICAL vulnerability).
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends openssh-client git \
    && rm -rf /var/lib/apt/lists/*
# One user per worker slot (app.run_isolation): the worker runs each slot's playbooks as
# ansideck-run<n>, uid/gid 20000+n, with no capabilities. ssh and ansible refuse to run as a
# uid without a passwd entry. The worker creates the homes (on its /tmp tmpfs) at startup.
RUN for n in $(seq 0 63); do \
      groupadd --gid $((20000 + n)) "ansideck-run$n" \
      && useradd --uid $((20000 + n)) --gid $((20000 + n)) --no-create-home \
         --home-dir "/tmp/ansideck-home/run$n" --shell /usr/sbin/nologin "ansideck-run$n"; \
    done
RUN useradd --create-home --uid 1000 appuser \
    && mkdir -p /data \
    && chown appuser:appuser /data
WORKDIR /app
COPY --from=build /app /app
# The license travels with the image (the named build context "repo" is the repository root:
# docker-compose.yml, and build-contexts in the workflows).
COPY --from=repo LICENSE /usr/share/licenses/ansideck/LICENSE
LABEL org.opencontainers.image.title="AnsiDeck backend" \
      org.opencontainers.image.description="AnsiDeck API and worker: run Ansible playbooks from a web UI" \
      org.opencontainers.image.source="https://github.com/HoneyBearTech/AnsiDeck" \
      org.opencontainers.image.url="https://github.com/HoneyBearTech/AnsiDeck" \
      org.opencontainers.image.documentation="https://github.com/HoneyBearTech/AnsiDeck/tree/main/docs" \
      org.opencontainers.image.licenses="MIT"
ENV PATH="/app/.venv/bin:$PATH"
USER appuser
# 8000: the API. 8001: the internal worker API (workers only; never publish it).
# 8002: Prometheus metrics, only when METRICS_TOKEN is set (scrapers only; never publish it).
# The same image runs a worker with the command: python -m app.worker, as root with only
# the SETUID, SETGID, CHOWN and KILL capabilities (see docker-compose.yml): it runs
# each slot's playbooks as that slot's own user, and refuses to start in production without.
EXPOSE 8000 8001 8002
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1
CMD ["fastapi", "run", "app/main.py", "--host", "0.0.0.0", "--port", "8000"]
