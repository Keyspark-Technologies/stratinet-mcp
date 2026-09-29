FROM python:3.12-slim-bookworm AS deps
COPY --from=ghcr.io/astral-sh/uv:0.12.19 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

FROM deps AS test
RUN uv sync --frozen
ENV PATH=/opt/venv/bin:$PATH
COPY . .
CMD ["sh", "-c", "ruff check . && ruff format --check . && pytest"]

FROM python:3.12-slim-bookworm AS runtime
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/bundle
RUN useradd --system --no-create-home --uid 10001 app
COPY --from=deps /opt/venv /opt/venv
WORKDIR /app
COPY server/ server/
COPY common/ common/
COPY engines/ engines/
USER 10001
EXPOSE 8000
CMD ["python", "-m", "server.main"]
