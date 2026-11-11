# PacketGuard AI — Real-Time Explainable Intrusion Detection

Hybrid ML (XGBoost + Isolation Forest) · SHAP explanations · human-approved response · MERN + Redpanda + FastAPI · Docker / Kubernetes / Jenkins.
Implements the Team 8 SRS and SDD (see `docs/`).

```
sniffer ──flow JSON──▶ Redpanda ──▶ ml-service (XGBoost + IsolationForest + SHAP) ──▶ MongoDB
(simulate/pcap/live)    topic: network-flows                                            │ change stream
                                                                       backend (Express + Socket.io + Prisma/SQLite)
                                                                                         │ REST + WebSocket
                                                                                  React dashboard (:3000)
```

## Run it (one command)

Requirements: Docker Desktop / Docker Engine with Compose v2, ~4 GB free RAM. Internet is needed for the first build.

```bash
cp .env.example .env          # optional: edit JWT_SECRET etc.
docker compose up --build
```

The first build takes several minutes: it installs dependencies and **trains the models inside the ml-service image**.
When the logs settle, open **http://localhost:3000** — alerts begin appearing within ~30 seconds.

| Role | Email | Password |
|---|---|---|
| Analyst | `analyst@packetguard.local` | `Analyst123` |
| Administrator | `admin@packetguard.local` | `Admin123` |

(Demo accounts are seeded only when the user table is empty; set `SEED_DEMO_USERS=false` to disable.)

Stop: `docker compose down` (add `-v` to wipe data).

## Demo script (matches SDD §11.9)
1. Sign in as analyst → Dashboard shows live counts and the alert feed.
2. Open a **critical** alert → read the SHAP bars ("why was this flagged?"), threat-intel panel, raw flow features.
3. **Acknowledge** → **Approve IP block** (a block is only allowed on an acknowledged alert; nothing is ever blocked automatically).
4. Open a second browser tab as another user — the status changes live in both.
5. Admin → *Pipeline & model* shows service health, metrics and the confusion matrix; *Detection thresholds* changes severity cut-offs (picked up by the ML service in ~15 s); *Audit log* shows every verdict and decision.

Look for alerts labelled **"Anomalous traffic"** — these come from the Isolation Forest alone (the simulator periodically emits an exfiltration-like family the classifier was never trained on).

## Traffic sources (`SNIFFER_MODE` in `.env`)
* `simulate` (default) — synthetic CICFlowMeter-style flows with random attack campaigns; no files needed. Tune with `FLOWS_PER_MINUTE`, `ATTACK_RATIO`.
* `pcap` — replays `sniffer/samples/demo.pcap` (generated at image build: benign web sessions + port scan + SYN flood) through the real Scapy flow assembler. Use your own file by mounting it and setting `PCAP_FILE`.
* `live` — sniffs a real interface (Linux: uncomment `network_mode: host` + `cap_add` in compose, set `CAPTURE_IFACE`). Only capture networks you are authorised to monitor.

## Train on real data (CIC-IDS2017)
The default models train on synthetic data, so their metrics (≈99 % F1) are optimistic — **do not quote them as real-world results**.
For real numbers: download the CIC-IDS2017 "MachineLearningCVE" CSVs, concatenate them into `data/cicids2017.csv`, then

```bash
DATASET_CSV=data/cicids2017.csv docker compose build ml-service && docker compose up -d
```
Column names are auto-mapped to the 12 features; labels are mapped to the 8 families (`ml-service/train.py`). Validate generalisation on UNSW-NB15 yourself and report the gap (FR-RPT-04).

## Optional integrations
Set in `.env`: `ABUSEIPDB_API_KEY` (otherwise a deterministic simulated lookup is shown, labelled as such), `SLACK_WEBHOOK_URL`, or `SMTP_*` + `ALERT_EMAIL_TO`. Critical alerts trigger them; without config they are logged.

## Develop without Docker
```bash
# infra only
docker compose up mongo redpanda -d
# backend
cd backend && npm install && cp ../.env.example .env   # then: export MONGO_URL=mongodb://localhost:27017/packetguard?directConnection=true DATABASE_URL=file:./dev.db KAFKA...
npx prisma db push && npm run dev
# frontend (proxies /api to :5000)
cd frontend && npm install && npm run dev      # http://localhost:3000
# ML + sniffer
pip install -r ml-service/requirements.txt -r sniffer/requirements.txt
cd ml-service && python train.py && KAFKA_BROKER=localhost:19092 ... uvicorn app:app
```
(The compose Redpanda only advertises its internal address; for host-side Python add an external listener or just run those two services in Docker.)

## Tests
```bash
cd backend && npm test                      # lifecycle + password policy
pip install -r ml-service/requirements.txt && pytest tests   # feature schema, flow assembly, fusion, SHAP, determinism, novel-traffic
```

## Kubernetes (Minikube)
```bash
./k8s/deploy-minikube.sh          # builds images in Minikube's Docker, applies k8s/*.yaml
minikube service frontend -n packetguard
```
Manifests: namespace/ConfigMap/Secret, Mongo StatefulSet + replica-set init Job, Redpanda, ml-service (+HPA 1–3), sniffer, backend (+PVC for SQLite), frontend (NodePort 30080). Probes use each service's `/health`.

## Jenkins
`Jenkinsfile`: parallel lint/tests → build 4 images → Trivy scan → push → `kubectl set image` + `rollout status` → smoke test. Needs Docker + kubectl on the agent and credentials `registry-creds` and `kubeconfig`; set the `REGISTRY` parameter. For Jira traceability put issue keys in commit messages.

## API summary
`POST /api/auth/{register,login,refresh,logout}` · `GET /api/alerts` (severity,status,srcIp,from,to,sort,page) · `GET /api/alerts/:id` · `GET /api/alerts/export` (CSV) · `PATCH /api/alerts/:id/status` · `POST /api/alerts/:id/block` · `GET|PATCH /api/blockrules` · `GET /api/stats/summary|model-performance` · `GET /api/threatintel/:ip` · `GET /api/notifications` · `/api/admin/{users,config,audit-logs,health}`.
Socket.io events: `new-alert`, `alert-updated`, `stats-updated` (≤1/s), `notification`. Errors: `{ "error": { "code", "message" } }`.

## Design notes & deliberate deviations from the documents
* **ML verdict audit**: the ML service writes alerts (with scores, SHAP and `modelVersion`) to MongoDB; the backend's change-stream watcher writes the `ML_VERDICT` audit row to SQLite. Benign flows are stored as raw flows only.
* **Self-registration** creates *Analyst* accounts only; admins create admins via Administration → Users.
* **Severity**: known attack → critical/high/medium by supervised confidence thresholds; anomaly-only → high/medium/low by anomaly score. All thresholds are admin-editable.
* **Transitions**: New→Acknowledged→Resolved/Blocked/False-positive (New→False-positive also allowed, per SDD Appendix D). Block requires an acknowledged alert.
* **Access tokens** live in memory only; the refresh token is an httpOnly cookie. Suspending a user revokes refresh tokens (an already-issued 15-min access token stays valid until it expires).
* **ml-service HPA 1–3**: with a single-partition topic only one consumer is active; create more partitions (and key by source IP) before scaling out inference.
* **Backend is 1 replica** because SQLite is a single-writer file; swap the Prisma datasource to Postgres to scale out.
* Settings page and password-reset (FR-AUTH-08, optional) are not implemented; Help/Terms/Privacy pages are not included.

## Known limitations
Simulated block rules only (no enforcement). Synthetic default dataset. `live` capture inside Docker Desktop on macOS/Windows only sees the VM's traffic. Built and unit-tested piecewise; run `docker compose up --build` first and check `docker compose logs` if a service fails to start.
