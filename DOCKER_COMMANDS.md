## Start and stop

```bash
docker compose up -d --build    # build and start in the background
docker compose down             # stop and remove containers (data kept)
docker compose down -v          # also delete volumes (wipes data)
```

## Inspect

```bash
docker compose ps               # container status
docker ps                       # all containers on this machine
docker compose logs --tail 50   # recent logs, all services
docker compose logs -f <name>   # follow one service
```

## Work on one service

```bash
docker compose up -d --build backend    # rebuild and restart only the backend
docker compose restart ml-service       # restart without rebuilding
docker compose exec backend sh          # open a shell in a running container
```

Service names: `mongo`, `redpanda`, `ml-service`, `sniffer`, `backend`, `frontend`.