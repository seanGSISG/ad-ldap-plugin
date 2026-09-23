# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------- #
# AD LDAP MCP server — permanent HTTP container.
#
# A builder stage resolves the locked runtime dependencies into a venv with uv;
# a slim production stage copies that venv plus the flat server modules and runs
# the bearer-protected streamable-HTTP transport as a non-root user.
#
# The server lives as flat modules under mcp/ (no build-system in pyproject), so
# we `uv sync` the dependency venv and run `python mcp/server.py` directly.
#
# Transport: HTTP on 0.0.0.0:8000, MCP mounted at /mcp (Authorization: Bearer
# <MCP_BEARER_TOKEN> required), unauthenticated /healthz liveness probe. Run as a
# long-lived container (docker compose up -d) — NOT per-connection like stdio.
# ---------------------------------------------------------------------------- #

# Build stage
FROM python:3.13-slim AS builder

WORKDIR /app

# Install uv (copy the static binaries into PATH).
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Copy only the dependency manifests first so the dependency layer is cached and
# only re-run when pyproject.toml / uv.lock change.
COPY pyproject.toml uv.lock ./

# Resolve the locked production dependencies into /app/.venv.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# Production stage
FROM python:3.13-slim AS production

# Create a non-root user to run the server.
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Copy the resolved virtual environment from the builder (no uv in production).
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}"

# Copy the flat server modules. server.py puts its own directory on sys.path so
# the sibling modules (app, ad_client, config, http_app, tools_*) import as
# top-level names.
COPY mcp/ /app/mcp/

# HTTP transport bind defaults + a conventional in-container CA-bundle path.
# Mount your DC's CA bundle at AD_CA_CERTS (e.g. -v ./cert/ldap-ca.pem:/certs/ldap-ca.pem:ro)
# or set AD_TLS_VALIDATE=false for a self-signed lab DC.
ENV HTTP_HOST=0.0.0.0 \
    HTTP_PORT=8000 \
    AD_CA_CERTS="/certs/ldap-ca.pem" \
    PYTHONUNBUFFERED=1

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Liveness probe against the unauthenticated /healthz endpoint.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"

LABEL org.opencontainers.image.title="ad-ldap-mcp"
LABEL org.opencontainers.image.description="FastMCP server wrapping ldap3 for Active Directory administration over LDAPS (HTTP transport)"

# Serve the bearer-protected HTTP transport on the container network.
CMD ["python", "/app/mcp/server.py", "--transport", "http"]
