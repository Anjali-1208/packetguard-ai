#!/usr/bin/env bash
# Build images inside Minikube's Docker daemon and deploy everything.
set -euo pipefail
cd "$(dirname "$0")/.."
minikube status >/dev/null 2>&1 || minikube start --memory 4096 --cpus 2
minikube addons enable metrics-server >/dev/null
eval "$(minikube docker-env)"
docker compose build
kubectl apply -f k8s/00-namespace-config.yaml
kubectl apply -f k8s/10-data.yaml
kubectl apply -f k8s/20-apps.yaml
kubectl -n packetguard rollout status statefulset/mongo --timeout=180s
kubectl -n packetguard rollout status deploy/backend --timeout=300s
kubectl -n packetguard get pods
echo; echo "Open the dashboard with:  minikube service frontend -n packetguard"
