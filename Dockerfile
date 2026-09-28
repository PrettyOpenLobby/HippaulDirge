# The Dirge of Cerberus world responder. One process, one UDP port (55040);
# docker-compose.yml passes the argument set.
#
# Built on the OpenLobby core image, which carries polcore (the PostgreSQL
# and Valkey layer every service shares), the core's account code the
# responder reads the POL sessions through, and their drivers. Build the core
# first, or point OPENLOBBY_IMAGE at the image you use.
ARG OPENLOBBY_IMAGE=openlobby:latest
FROM ${OPENLOBBY_IMAGE}

WORKDIR /app
COPY tools/ /app/

RUN python - <<'EOF'
import os, sys
if not os.path.isdir("polcore") or not os.path.isfile("accounts.py"):
    sys.exit("the base image has no polcore/ or accounts.py - build it FROM the OpenLobby image")
if not os.path.isdir("doc_migrations"):
    sys.exit("tools/doc_migrations/ is missing from the build context")
EOF

ENV PYTHONUNBUFFERED=1
EXPOSE 55040/udp
ENTRYPOINT ["python", "docudp.py"]
