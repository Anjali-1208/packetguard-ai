import json, logging, os, threading, time
from datetime import datetime, timezone
from bson import ObjectId
from pymongo import MongoClient
from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
from confluent_kafka import Consumer, KafkaException
from pg_common.features import FEATURES, row_from_dict
from pg_common.kafka_util import ensure_topic
from scoring import Scorer, SEV_RANK, DEFAULT_THRESHOLDS

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("ml-service")

BROKER = os.environ.get("KAFKA_BROKER", "redpanda:9092")
TOPIC = os.environ.get("KAFKA_TOPIC", "network-flows")
MONGO_URL = os.environ.get("MONGO_URL", "mongodb://mongo:27017/packetguard?directConnection=true")

state = {"scorer": None, "db": None, "processed": 0, "alerts": 0, "failures": 0,
         "avg_ms": 0.0, "last_event": None, "consumer_alive": False, "thresholds": dict(DEFAULT_THRESHOLDS),
         "th_loaded": 0.0}
stop = threading.Event()


def thresholds():
    if time.time() - state["th_loaded"] > 15:
        try:
            doc = state["db"].config.find_one({"_id": "severity"})
            if doc:
                state["thresholds"] = {**DEFAULT_THRESHOLDS, **{k: v for k, v in doc.items() if k != "_id"}}
        except Exception as e:
            log.warning("threshold refresh failed: %s", e)
        state["th_loaded"] = time.time()
    return state["thresholds"]


def process_event(raw: bytes):
    ev = json.loads(raw)
    feats = ev["features"] if isinstance(ev.get("features"), list) else row_from_dict(ev["features"])
    if len(feats) != len(FEATURES):
        raise ValueError(f"expected {len(FEATURES)} features, got {len(feats)}")
    t0 = time.time()
    res = state["scorer"].score(feats, thresholds())
    ms = (time.time() - t0) * 1000
    db = state["db"]
    flow_id = ObjectId(ev["flowId"]) if ev.get("flowId") else None
    if flow_id is not None:
        db.flows.update_one({"_id": flow_id}, {"$set": {"verdict": res["verdict"], "supervisedLabel": res["supervisedLabel"]}})
    if res["verdict"] == "malicious":
        db.alerts.insert_one({
            **res, "flowId": flow_id, "srcIp": ev["srcIp"], "dstIp": ev["dstIp"],
            "srcPort": ev.get("srcPort"), "dstPort": ev.get("dstPort"), "protocol": ev.get("protocol"),
            "features": dict(zip(FEATURES, feats)), "severityRank": SEV_RANK[res["severity"]],
            "status": "new", "assignedToUserId": None, "processingMs": round(ms, 1),
            "createdAt": datetime.now(timezone.utc),
        })
        state["alerts"] += 1
    n = state["processed"] + 1
    state["avg_ms"] = (state["avg_ms"] * (n - 1) + ms) / n
    state["processed"] = n
    state["last_event"] = datetime.now(timezone.utc).isoformat()


def consume_loop():
    ensure_topic(BROKER, TOPIC)
    c = Consumer({"bootstrap.servers": BROKER, "group.id": "ml-service", "enable.auto.commit": False,
                  "auto.offset.reset": "earliest", "allow.auto.create.topics": True})
    c.subscribe([TOPIC]); state["consumer_alive"] = True
    log.info("consuming %s from %s", TOPIC, BROKER)
    while not stop.is_set():
        msg = c.poll(1.0)
        if msg is None: continue
        if msg.error():
            log.warning("kafka: %s", msg.error()); continue
        for attempt in range(1, 4):
            try:
                process_event(msg.value()); break
            except Exception as e:
                log.warning("scoring attempt %s/3 failed: %s", attempt, e)
                time.sleep(0.5 * 2 ** (attempt - 1))
        else:
            state["failures"] += 1
            try:
                state["db"].processing_failures.insert_one({"at": datetime.now(timezone.utc), "payloadBytes": len(msg.value() or b"")})
            except Exception: pass
            log.error("event skipped after 3 attempts (offset %s)", msg.offset())
        c.commit(msg)  # commit only after a successful write or a logged failure
    c.close()


@asynccontextmanager
async def lifespan(app):
    state["scorer"] = Scorer()
    log.info("models loaded, version %s", state["scorer"].version)
    client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=60000)
    state["db"] = client.get_default_database()
    state["db"].alerts.create_index([("severity", 1), ("status", 1), ("createdAt", -1)])
    state["db"].alerts.create_index("srcIp")
    state["db"].flows.create_index("timestamp"); state["db"].flows.create_index("srcIp")
    threading.Thread(target=consume_loop, daemon=True).start()
    yield
    stop.set()


app = FastAPI(title="PacketGuard ML service", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok" if state["consumer_alive"] else "starting", "modelVersion": state["scorer"].version if state["scorer"] else None,
            "processed": state["processed"], "alerts": state["alerts"], "failures": state["failures"],
            "avgScoringMs": round(state["avg_ms"], 1), "lastEvent": state["last_event"]}


@app.get("/model/metrics")
def model_metrics():
    return state["scorer"].metrics


@app.post("/score")
def score_one(body: dict):
    """Score a single flow without persisting (handy for manual testing)."""
    try:
        feats = body["features"] if isinstance(body.get("features"), list) else row_from_dict(body.get("features", body))
        return state["scorer"].score(feats, thresholds())
    except Exception as e:
        raise HTTPException(400, str(e))
