FROM python:3-slim

ARG HOST=0.0.0.0
ARG PORT=8024
ENV HOST=${HOST}
ENV PORT=${PORT}
ENV PATH="/usr/local/bin:${PATH}"
RUN apt update \
    && apt install -y \
    && pip install uv \
    && uv pip install --system tunnel-manager
ENTRYPOINT exec tunnel-manager-mcp --transport "http" --host "${HOST}" --port "${PORT}"
