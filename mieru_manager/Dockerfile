FROM python:3.13.5-slim@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419
RUN groupadd --system --gid 10003 mieru-manager \
 && useradd --system --uid 10003 --gid mieru-manager --no-create-home mieru-manager
WORKDIR /app
COPY mieru_manager /app/mieru_manager
USER 10003:10003
ENTRYPOINT ["python", "-m", "mieru_manager"]
