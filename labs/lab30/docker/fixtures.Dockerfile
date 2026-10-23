FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
COPY fixtures/server.py /srv/server.py
USER 65534:65534
EXPOSE 8080 8082
CMD ["python", "-B", "/srv/server.py"]
