# ============================================================
#  Config — Pydantic Settings (reads from .env automatically)
# ============================================================

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────
    app_env: str = Field(default="development")
    log_level: str = Field(default="INFO")
    simulation_mode: bool = Field(default=True)

    # ── Kafka ────────────────────────────────────────────────
    kafka_bootstrap_servers: str = Field(default="localhost:9093")
    kafka_topic_raw: str = Field(default="raw-events")
    kafka_topic_normalized: str = Field(default="normalized-events")
    kafka_topic_alerts: str = Field(default="threat-alerts")
    kafka_topic_actions: str = Field(default="defense-actions")
    kafka_consumer_group: str = Field(default="threat-hunter-group")

    # ── Neo4j ────────────────────────────────────────────────
    neo4j_uri: str = Field(default="bolt://127.0.0.1:7687")
    neo4j_user: str = Field(default="neo4j")
    neo4j_password: str = Field(default="threatpassword123")

    # ── Redis ────────────────────────────────────────────────
    redis_host: str = Field(default="localhost")
    redis_port: int = Field(default=6379)
    redis_password: str = Field(default="redispass123")

    # ── LLM ──────────────────────────────────────────────────
    llm_provider: str = Field(default="groq")  # "groq", "ollama", or "openai"
    ollama_base_url: str = Field(default="http://localhost:11434")
    ollama_model: str = Field(default="llama3")
    openai_api_key: str = Field(default="")
    openai_model: str = Field(default="gpt-4o-mini")
    groq_api_key: str = Field(default="")
    groq_model: str = Field(default="llama-3.3-70b-versatile")

    # ── Threat Intel ─────────────────────────────────────────
    otx_api_key: str = Field(default="")
    threat_intel_poll_min: int = Field(default=15)

    # ── AI Model ─────────────────────────────────────────────
    prediction_interval_sec: int = Field(default=30)
    gnn_hidden_channels: int = Field(default=64)
    gnn_num_layers: int = Field(default=3)
    threat_score_threshold: float = Field(default=0.65)

    # ── Responsible AI ───────────────────────────────────────
    require_human_approval_for_high: bool = Field(default=True)
    audit_log_path: str = Field(default="audit_logs/audit.jsonl")


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton — call get_settings() anywhere."""
    return Settings()
