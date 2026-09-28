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

# tools/ lands on top of the core's modules, so refuse an image in which a
# stray copy has replaced the core's live_sessions.py, which publishes the
# deploy gate's count of connected consoles (.dockerignore keeps one out of
# the build context)
RUN python -c "import sys, live_sessions; hasattr(live_sessions, 'marker_key') or sys.exit('live_sessions.py is not the one from the OpenLobby image')"

ENV PYTHONUNBUFFERED=1
EXPOSE 55040/udp
ENTRYPOINT ["python", "docudp.py"]
