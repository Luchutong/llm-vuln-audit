# Reuse the runner's base image. No registry-only utility image, build frontend,
# apt packages or Python dependencies are needed for the development bridge.
FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
COPY relay.py /app/relay.py
USER 10002:10002
EXPOSE 8080
ENTRYPOINT ["python", "-I", "/app/relay.py"]
