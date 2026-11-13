# gpuwatch hub: agentless, nvtop-style GPU dashboard (collects over SSH)
FROM python:3.12-alpine

RUN apk add --no-cache openssh-client su-exec \
 && mkdir -p /app /data

WORKDIR /app
COPY gpuwatch.py dashboard.html /app/
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 0644 /app/gpuwatch.py /app/dashboard.html && chmod 0755 /entrypoint.sh

ENV GPUWATCH_DATA=/data \
    HOME=/data \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

VOLUME /data
EXPOSE 9180

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- "http://127.0.0.1:${GPUWATCH_PORT:-9180}/healthz" >/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
