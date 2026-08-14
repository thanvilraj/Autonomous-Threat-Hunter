# ============================================================
#  Module A — Kafka Consumer & Graph Builder
#
#  Consumes raw events from Kafka, validates + normalizes them,
#  then writes them to Neo4j via the Neo4jMapper.
# ============================================================

import json
import signal
import sys
from loguru import logger
from confluent_kafka import Consumer, KafkaError, KafkaException

from src.config.settings import get_settings
from src.module_a.event_schemas import parse_event, BaseEvent
from src.module_a.neo4j_mapper import Neo4jMapper


class ThreatHunterConsumer:
    """
    Kafka consumer that reads raw events, validates them,
    and feeds the Neo4j graph builder.
    """

    def __init__(self):
        self.settings = get_settings()
        self.mapper = Neo4jMapper()
        self._consumer = self._create_consumer()
        self._running = True

        # Graceful shutdown on SIGINT / SIGTERM
        signal.signal(signal.SIGINT,  self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _create_consumer(self) -> Consumer:
        conf = {
            "bootstrap.servers":   self.settings.kafka_bootstrap_servers,
            "group.id":            self.settings.kafka_consumer_group,
            "auto.offset.reset":   "earliest",
            "enable.auto.commit":  False,   # Manual commit for reliability
            "max.poll.interval.ms": 300000,
            "session.timeout.ms":   30000,
        }
        logger.info(f"🔌 Connecting consumer to Kafka: {self.settings.kafka_bootstrap_servers}")
        return Consumer(conf)

    def _shutdown(self, signum, frame):
        logger.info("🛑 Shutdown signal received — stopping consumer gracefully...")
        self._running = False

    def _process_message(self, raw_value: bytes) -> None:
        """Decode, validate, and ingest a single Kafka message."""
        try:
            data = json.loads(raw_value.decode("utf-8"))
            event: BaseEvent = parse_event(data)
            self.mapper.ingest_event(event)
            logger.info(
                f"📥 Ingested | type={event.event_type.value} | "
                f"host={event.source_host} | severity={event.severity.value}"
            )
        except json.JSONDecodeError as e:
            logger.error(f"❌ JSON decode error: {e} | raw={raw_value[:200]}")
        except Exception as e:
            logger.exception(f"❌ Failed to process message: {e}")

    def run(self) -> None:
        """Main consumer loop — blocks until shutdown signal."""
        topics = [
            self.settings.kafka_topic_raw,
            self.settings.kafka_topic_normalized,
        ]
        try:
            self.mapper.connect()
            self._consumer.subscribe(topics)
            logger.success(f"✅ Consumer subscribed to topics: {topics}")

            while self._running:
                msg = self._consumer.poll(timeout=1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        logger.debug("Reached partition EOF, waiting for more...")
                        continue
                    raise KafkaException(msg.error())

                self._process_message(msg.value())
                self._consumer.commit(asynchronous=False)  # Manual commit

        except KafkaException as e:
            logger.critical(f"💥 Kafka error: {e}")
            sys.exit(1)
        finally:
            self._consumer.close()
            self.mapper.close()
            logger.info("🔒 Consumer and Neo4j connections closed")


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    consumer = ThreatHunterConsumer()
    consumer.run()
