FROM python:3-slim

ARG HOST=0.0.0.0
ARG PORT=8024
ARG TRANSPORT="http"
ENV HOST=${HOST}
ENV PORT=${PORT}
ENV TRANSPORT=${TRANSPORT}
ENV PATH="/usr/local/bin:${PATH}"
RUN pip install uv \
    && uv pip install --system tunnel-manager>=1.0.2
ENTRYPOINT exec tunnel-manager-mcp --transport "${TRANSPORT}" --host "${HOST}" --port "${PORT}"
