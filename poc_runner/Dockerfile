# syntax=docker/dockerfile:1
#
# The isolated POC executor.  It is intentionally a separate image: the audit app
# carries no PHP runtime and never launches a script, while this container carries no
# audit database, no uploaded archive and no model credential.
FROM python:3.12-slim-bookworm

ARG INSTALL_BROWSER=1
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    POC_RUNNER_WORKDIR=/tmp/poc-runner \
    HOME=/tmp \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

RUN apt-get update \
    && apt-get install -y --no-install-recommends php-cli php-curl curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# XSS confirmation needs a real browser.  With INSTALL_BROWSER=0 the runner reports
# browser_unavailable instead, and a run can only record such findings as inconclusive.
RUN if [ "$INSTALL_BROWSER" = "1" ]; then \
        pip install --no-cache-dir "playwright==1.48.0" \
        && python -m playwright install --with-deps chromium \
        && chmod -R a+rX /ms-playwright; \
    fi

RUN groupadd --gid 10002 runner \
    && useradd --uid 10002 --gid runner --no-create-home --shell /usr/sbin/nologin runner \
    && mkdir -p /app /tmp/poc-runner \
    && chown -R runner:runner /app /tmp/poc-runner

COPY runner.py /app/runner.py

USER 10002:10002
EXPOSE 8080

# -I keeps the interpreter from reading PYTHON* variables or the working directory.
ENTRYPOINT ["python", "-I", "/app/runner.py"]
