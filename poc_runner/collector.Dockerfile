FROM python:3.12-slim-bookworm

WORKDIR /app
COPY collector.py /app/collector.py
RUN useradd --uid 10003 --no-create-home --shell /usr/sbin/nologin diagnostics \
    && chown -R 10003:10003 /app
USER 10003:10003
EXPOSE 8091
CMD ["python", "-I", "collector.py"]
