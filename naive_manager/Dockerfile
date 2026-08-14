FROM python:3.13.5-slim@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    NAIVE_CADDYFILE=/data/Caddyfile NAIVE_STATE_FILE=/data/users.json \
    NAIVE_BACKUP_DIR=/data/backups NAIVE_MANAGER_SOCKET=/run/naive-manager/manager.sock \
    NAIVE_MANAGER_TOKEN_FILE=/run/secrets/naive-manager-token
WORKDIR /app
COPY naive_manager /app/naive_manager
ENTRYPOINT ["python", "-m", "naive_manager.server"]
