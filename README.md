# Autonomous Threat Hunting & Attack-Path Prediction

> **Final Year Project** | Cybersecurity & AI Domain

A production-grade AI system that detects cyber attacks in real-time, predicts attacker lateral movement using Graph Neural Networks, and auto-generates incident reports in plain English.

---

## Target Metrics
| Metric | Target |
|---|---|
| Attack path prediction accuracy | > 90% |
| Threat detection speed improvement | > 70% faster |
| Manual analyst workload reduction | > 60% |

---

## Architecture

```
Network Events → Kafka → Neo4j Graph → GNN (PyTorch) → MITRE ATT&CK → LLM Reports
```

---

## Quick Start

### 1. Prerequisites
- Docker Desktop (with Docker Compose v2)
- Python 3.11+
- 8GB+ RAM recommended

### 2. Clone & Configure
```bash
git clone <your-repo>
cd autonomous-threat-hunter
cp .env.example .env
# Edit .env with your API keys (OTX, OpenAI optional)
```

### 3. Start the Stack
```bash
docker compose up -d
```

Wait ~60 seconds for all services to start, then check:
- **Neo4j Browser**: http://localhost:7474 (user: neo4j, pass: threatpassword123)
- **API Docs**: http://localhost:8000/docs
- **Ollama**: http://localhost:11434

### 4. Pull the LLM Model (first time only)
```bash
docker exec -it ollama ollama pull llama3
```

### 5. Start the Event Simulator (Module A)
```bash
# In a new terminal — simulates an APT attack
python -m src.module_a.kafka_producer apt

# Or continuous random events
python -m src.module_a.kafka_producer random
```

### 6. Start the Consumer (graph builder)
```bash
python -m src.module_a.kafka_consumer
```

### 7. Run the API
```bash
uvicorn src.api.main:app --reload
```

---

## Project Structure

```
autonomous-threat-hunter/
├── docker-compose.yml          # Full stack infrastructure
├── Dockerfile                  # App container
├── requirements.txt            # Python dependencies
├── .env.example                # Environment template
│
├── src/
│   ├── config/
│   │   └── settings.py         # Pydantic settings (reads .env)
│   │
│   ├── module_a/               # Data Collection & Graph Mapping
│   │   ├── event_schemas.py    # Pydantic event models
│   │   ├── kafka_producer.py   # APT simulator / log ingestor
│   │   ├── kafka_consumer.py   # Consumer → Neo4j pipeline
│   │   └── neo4j_mapper.py     # Cypher graph builder
│   │
│   ├── module_b/               # AI Prediction & Threat Defense
│   │   ├── gnn_model.py        # PyTorch Geometric GraphSAGE
│   │   ├── attack_predictor.py # Orchestrates prediction cycles
│   │   ├── mitre_mapper.py     # MITRE ATT&CK pattern mapping
│   │   ├── defense_engine.py   # Tiered recommendations + approval gate
│   │   └── audit_logger.py     # Append-only JSONL audit trail
│   │
│   ├── module_c/               # LLM Explanations & Threat Intel
│   │   ├── langchain_reporter.py # LangChain incident reports
│   │   └── threat_intel.py     # OTX + NVD threat feed polling
│   │
│   └── api/
│       └── main.py             # FastAPI REST API
│
├── data/
│   ├── mitre/                  # Place enterprise-attack.json here
│   └── models/                 # Saved GNN weights
│
└── tests/
    ├── test_module_a.py        # Event schema tests
    └── test_module_b.py        # GNN + MITRE + Defense tests
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Health check |
| GET | `/threats` | Run prediction cycle, return threats |
| GET | `/graph/snapshot` | Full Neo4j graph as JSON |
| GET | `/graph/high-risk` | Nodes above risk threshold |
| POST | `/incidents/generate` | Generate LLM incident report |
| GET | `/actions/pending` | HIGH/CRITICAL actions awaiting approval |
| POST | `/actions/approve` | **Human approval gate** |
| GET | `/mitre/techniques` | All MITRE ATT&CK techniques |
| GET | `/audit` | Full audit trail |
| GET | `/intel/summary` | Threat intel feed status |

---

## Responsible AI Guardrails

| Rule | Implementation |
|---|---|
| Defensive-only | System cannot initiate attacks — read-only by default |
| Human approval | HIGH/CRITICAL actions queued in Redis, require `POST /actions/approve` |
| Full audit trail | Every AI decision logged to append-only JSONL with model version + confidence |
| Confidence scoring | Every recommendation includes a threat score (0.0–1.0) |
| Explainability | LLM generates plain-English justification for every alert |

---

## Tech Stack
- **Apache Kafka** — Real-time event streaming
- **Neo4j** — Graph database for network topology
- **PyTorch Geometric** — GraphSAGE GNN model
- **LangChain + Ollama** — Local LLM incident reporting
- **FastAPI** — REST API layer
- **Docker Compose** — Full-stack orchestration

---

## Running Tests
```bash
pip install -r requirements.txt
pytest tests/ -v --cov=src --cov-report=term-missing
```
