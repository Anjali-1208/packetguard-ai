# Requirement → implementation map

| SRS requirement | Where it lives |
|---|---|
| FR-AUTH-01..07, 09 | `backend/src/routes/auth.js`, `routes/admin.js` (create user), `middleware/auth.js`, `socket.js` (handshake JWT) |
| FR-CAP-01..06 | `sniffer/sniffer.py` (simulate / pcap / live), `sniffer/flow_table.py` |
| FR-DETECT-01..08 | `ml-service/scoring.py` (fusion, SHAP, schema), `ml-service/app.py` (consumer, retry×3, commit-after-write) |
| FR-SCORE-01..05 | `scoring.py` (severity), `frontend/src/components/ui.jsx` (`ContribChart`), Admin → thresholds |
| FR-INTEL-01..03 | `backend/src/services/threatintel.js` (24 h cache, graceful failure) |
| FR-RESP-01..09 | `backend/src/routes/alerts.js`, `services/transitions.js`, `frontend/src/pages/Alerts*.jsx` |
| FR-NOT-01..04 | `backend/src/services/watcher.js`, `notify.js`, `socket.js`; `pages/Notifications.jsx` |
| FR-DASH / FR-ADM / FR-RPT | `pages/Dashboard.jsx`, `pages/Admin.jsx`, `routes/admin.js`, `services/stats.js` |
| FR-LOG-01..06 | `services/audit.js` (append-only AuditLog table), watcher writes `ML_VERDICT` rows |
| PERF-09 determinism | `tests/test_pipeline.py::test_inference_is_deterministic` |
| SEC-01..07 | bcrypt(12), helmet, CORS, rate limit, zod validation, no payload capture, secrets via env |
| REL / AVL / POR / SCA | `docker-compose.yml` healthchecks + restart policy, `k8s/` probes + HPA, env-only config |
| CI/CD | `Jenkinsfile` |
