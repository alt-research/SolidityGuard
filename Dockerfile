# SolidityGuard CLI — Solidity security audit tool
# Usage:
#   docker build -t solidityguard .
#   docker run -v ./contracts:/audit solidityguard audit /audit
#   docker run -v ./contracts:/audit solidityguard scan /audit --category reentrancy
#   docker run -v ./contracts:/audit solidityguard audit --quick /audit -o /audit/findings.json

FROM python:3.12-slim AS base

LABEL maintainer="Alt Research Ltd."
LABEL description="SolidityGuard — Solidity smart contract security audit"
LABEL version="1.2.1"

# System deps for weasyprint PDF generation + build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry (forge, cast, anvil)
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:${PATH}"

# Install Slither
RUN pip install --no-cache-dir slither-analyzer

# Install Mythril
RUN pip install --no-cache-dir mythril || true

# Install Halmos
RUN pip install --no-cache-dir halmos || true

# Install weasyprint + markdown for PDF reports
RUN pip install --no-cache-dir weasyprint markdown

WORKDIR /app

# Copy scanner scripts (core engine)
COPY .claude/skills/solidity-guard/scripts/ /app/scripts/

# Copy and install CLI
COPY apps/cli/ /app/cli/
RUN pip install --no-cache-dir /app/cli/

# Copy knowledge base
COPY knowledge-base/ /app/knowledge-base/

ENTRYPOINT ["solidityguard"]
CMD ["--help"]
