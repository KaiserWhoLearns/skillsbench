FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nodejs \
    npm \
    curl \
    git \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages for license scanning and reporting
RUN pip3 install --break-system-packages \
    openpyxl==3.1.5 \
    requests==2.32.3

# Copy project dependencies and policy files
COPY project_dependencies.json /root/project_dependencies.json
COPY license_policy.json /root/license_policy.json

# Copy skills to all agent paths
COPY skills /root/.claude/skills
COPY skills /root/.codex/skills
COPY skills /root/.opencode/skills
COPY skills /root/.goose/skills
COPY skills /root/.factory/skills
COPY skills /root/.agents/skills

WORKDIR /root
