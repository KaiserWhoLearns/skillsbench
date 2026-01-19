FROM python:3.11-slim

WORKDIR /app

RUN mkdir -p /app/data /app/output

COPY data/ /app/data/
COPY skills/ /app/skills/

# Copy skills to agent-specific locations
COPY skills /root/.claude/skills
COPY skills /root/.codex/skills
COPY skills /root/.opencode/skills
COPY skills /root/.goose/skills
COPY skills /root/.factory/skills
COPY skills /root/.agents/skills

CMD ["/bin/bash"]
