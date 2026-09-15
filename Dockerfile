# The Dirge of Cerberus world responder. One process, one UDP port (55040),
# standard library only; docker-compose.yml passes the argument set.
# Digest pinned 2026-09-15; bump deliberately, not by surprise.
FROM python:3.12-slim@sha256:2fe5997d249a808b8eeea52c58a1dbffbba28754dc11699ef5c029f2d818ce79

WORKDIR /app
COPY tools/ /app/

ENV PYTHONUNBUFFERED=1
EXPOSE 55040/udp
ENTRYPOINT ["python", "docudp.py"]
