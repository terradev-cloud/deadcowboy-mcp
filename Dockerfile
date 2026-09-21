FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

# The drop ledger persists on the /data volume -- the default
# ~/.deadcowboy path is container-local and every recreate would wipe it.
ENV DEADCOWBOY_DB=/data/drops.db
ENV DEADCOWBOY_PORT=8000

CMD ["deadcowboy-mcp-http"]
