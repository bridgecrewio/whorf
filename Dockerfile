FROM python:3.10-slim

# mention "admissionController" as the source of integration to bridgecrew.cloud
ENV BC_SOURCE=admissionController
ENV RUN_IN_DOCKER=True

RUN set -eux; \
    apt-get update; \
    apt-get -y --no-install-recommends upgrade; \
    apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt checkov-requirements.txt ./

RUN set -eux; \
    pip install -r requirements.txt; \
    pip install -r checkov-requirements.txt

COPY whorf.py wsgi.py ./

# create the app user
RUN set -eux; \
    addgroup --gid 11000 app; \
    adduser --disabled-password --gecos "" --uid 11000 --ingroup app app; \
    # chown all the files to the app user
    chown -R app:app /app

# change to the app user
USER app

CMD gunicorn --certfile=/certs/webhook.crt --keyfile=/certs/webhook.key --bind 0.0.0.0:8443 wsgi:webhook
