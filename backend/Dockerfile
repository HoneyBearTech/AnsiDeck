FROM python:3.12-slim AS base
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
WORKDIR /app

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

FROM python:3.12-slim AS runtime
RUN useradd --create-home --uid 1000 appuser
WORKDIR /app
COPY --from=build /app /app
ENV PATH="/app/.venv/bin:$PATH"
USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1
CMD ["fastapi", "run", "app/main.py", "--host", "0.0.0.0", "--port", "8000"]
