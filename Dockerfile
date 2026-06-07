FROM python:3.11-slim

WORKDIR /app
COPY . /app

# install with the MCP extra so `synthesis serve` works out of the box
RUN pip install --no-cache-dir ".[mcp]"

# local Intent Graph + models live on a volume (NOT a network mount — sqlite needs
# real file locking). See docker-compose.yml.
ENV SYNTHESIS_DB=/data/intent_graph.db \
    SYNTHESIS_MODELS_DIR=/data/models \
    SYNTHESIS_SKILLS_DIR=/app/skills
VOLUME ["/data"]

ENTRYPOINT ["synthesis"]
CMD ["serve"]
