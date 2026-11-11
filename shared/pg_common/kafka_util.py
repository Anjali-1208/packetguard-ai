import logging, time
from confluent_kafka.admin import AdminClient, NewTopic

log = logging.getLogger("pg.kafka")


def ensure_topic(bootstrap: str, topic: str, partitions: int = 1, retries: int = 30):
    """Create the topic if missing; waits for the broker to come up."""
    admin = AdminClient({"bootstrap.servers": bootstrap})
    for attempt in range(retries):
        try:
            md = admin.list_topics(timeout=5)
            if topic in md.topics and md.topics[topic].error is None:
                return True
            futs = admin.create_topics([NewTopic(topic, num_partitions=partitions, replication_factor=1)])
            for f in futs.values():
                try:
                    f.result()
                except Exception as e:  # already exists is fine
                    if "TOPIC_ALREADY_EXISTS" not in str(e):
                        raise
            return True
        except Exception as e:
            log.warning("waiting for broker (%s/%s): %s", attempt + 1, retries, e)
            time.sleep(2)
    return False
