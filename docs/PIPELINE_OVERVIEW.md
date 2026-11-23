# Pipeline Overview

1. **Sniffer** produces network flow records (simulated, replayed from a pcap, or captured live) and publishes them to the Redpanda topic `network-flows`.
2. **ml-service** consumes each flow, scores it with XGBoost (known attacks) and Isolation Forest (anomalies), adds SHAP explanations, and stores alerts in MongoDB.
3. **backend** watches MongoDB for new alerts, stores audit records, and serves the REST API and Socket.io events.
4. **frontend** shows live alerts, severity, explanations, and analyst actions.

Blocking an IP is never automatic. An analyst must acknowledge the alert and then approve the block.