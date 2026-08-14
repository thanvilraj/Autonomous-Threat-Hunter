#!/bin/bash
# ============================================================
#  Autonomous Threat Hunter — Full Environment Setup Script
#  Run: bash setup.sh
# ============================================================

set -e   # Exit on any error
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$PROJECT_DIR/.venv"
PYTHON="python3"
PIP="$VENV_DIR/bin/pip"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Autonomous Threat Hunter — Environment Setup       ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: System Dependencies (macOS) ─────────────────────
echo "▶ [1/7] Checking system dependencies..."

if ! command -v brew &> /dev/null; then
    echo "❌ Homebrew not found. Install it from https://brew.sh"
    exit 1
fi

# librdkafka (required by confluent-kafka)
if ! brew list librdkafka &>/dev/null; then
    echo "  Installing librdkafka (required for Kafka)..."
    brew install librdkafka
else
    echo "  ✅ librdkafka already installed"
fi

# ── Step 2: Python Virtual Environment ──────────────────────
echo ""
echo "▶ [2/7] Creating Python virtual environment at .venv ..."
$PYTHON -m venv "$VENV_DIR"
echo "  ✅ Virtual environment created"

# Activate for this script
source "$VENV_DIR/bin/activate"

# ── Step 3: Upgrade pip ──────────────────────────────────────
echo ""
echo "▶ [3/7] Upgrading pip, setuptools, wheel..."
$PIP install --upgrade pip setuptools wheel --quiet
echo "  ✅ pip upgraded"

# ── Step 4: Install PyTorch (CPU — Mac ARM64 / x86) ─────────
echo ""
echo "▶ [4/7] Installing PyTorch 2.3.0 (CPU)..."
$PIP install torch==2.13.0 --index-url https://download.pytorch.org/whl/cpu --quiet
echo "  ✅ PyTorch installed"

# ── Step 5: Install PyTorch Geometric + dependencies ────────
# torch-scatter and torch-sparse MUST come from PyG wheel index
echo ""
echo "▶ [5/7] Installing PyTorch Geometric & graph dependencies..."
$PIP install torch-geometric==2.5.3 --quiet
$PIP install torch-scatter torch-sparse \
    -f https://data.pyg.org/whl/torch-2.13.0+cpu.html --quiet
echo "  ✅ PyTorch Geometric installed"

# ── Step 6: Install remaining dependencies ───────────────────
echo ""
echo "▶ [6/7] Installing all remaining project dependencies..."

# Install confluent-kafka with the system librdkafka
C_INCLUDE_PATH="$(brew --prefix librdkafka)/include" \
LIBRARY_PATH="$(brew --prefix librdkafka)/lib" \
$PIP install confluent-kafka==2.4.0 --quiet

# Install everything else from requirements.txt
# Skip already-installed torch packages to avoid conflicts
$PIP install \
    fastapi==0.111.0 \
    "uvicorn[standard]==0.29.0" \
    pydantic==2.7.1 \
    pydantic-settings==2.3.0 \
    python-dotenv==1.0.1 \
    neo4j==5.20.0 \
    redis==5.0.4 \
    scikit-learn==1.5.0 \
    numpy==1.26.4 \
    pandas==2.2.2 \
    networkx==3.3 \
    langchain==0.2.5 \
    langchain-community==0.2.5 \
    langchain-ollama==0.1.1 \
    langchain-openai==0.1.9 \
    openai==1.30.5 \
    requests==2.32.3 \
    aiohttp==3.9.5 \
    rich==13.7.1 \
    loguru==0.7.2 \
    httpx==0.27.0 \
    tenacity==8.3.0 \
    apscheduler==3.10.4 \
    pytest==8.2.2 \
    pytest-asyncio==0.23.7 \
    pytest-cov==5.0.0 \
    OTXv2==1.5.12 \
    --quiet

echo "  ✅ All dependencies installed"

# ── Step 7: Copy env file ────────────────────────────────────
echo ""
echo "▶ [7/7] Setting up .env configuration..."
if [ ! -f "$PROJECT_DIR/.env" ]; then
    cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
    echo "  ✅ .env created from template — edit it with your API keys"
else
    echo "  ✅ .env already exists"
fi

# ── Create data directories ──────────────────────────────────
mkdir -p "$PROJECT_DIR/data/mitre"
mkdir -p "$PROJECT_DIR/data/models"
mkdir -p "$PROJECT_DIR/audit_logs"

# ── Done ─────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   ✅ Setup Complete!                                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  1. Activate the venv:  source .venv/bin/activate"
echo "  2. Start the stack:    docker compose up -d"
echo "  3. Pull the LLM:       docker exec -it ollama ollama pull llama3"
echo "  4. Run tests:          pytest tests/ -v"
echo ""
echo "Installed packages summary:"
"$VENV_DIR/bin/pip" list | grep -E "torch|kafka|neo4j|langchain|fastapi|redis|pydantic" | column -t
echo ""
