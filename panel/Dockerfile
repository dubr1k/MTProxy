FROM python:3.13.5-slim@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt \
 && addgroup --system panel && adduser --system --ingroup panel --uid 10001 panel \
 && mkdir -p /data && chown panel:panel /data
COPY --chown=panel:panel . /app/panel
RUN chmod 0755 /app/panel/entrypoint.sh /app/panel/stage_secret.py
EXPOSE 8787
ENTRYPOINT ["/app/panel/entrypoint.sh"]
