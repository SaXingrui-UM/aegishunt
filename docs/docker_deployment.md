# Docker Compose deployment

## Local research topology

`compose.yaml` defines `init`, `api`, `worker`, and `frontend`. It uses one
dedicated bridge network and three named volumes (`data`, `artifacts`, `reports`).
The API and Streamlit ports publish to host loopback only. The deployment has no
host networking, privileged container, added capability, Docker-socket mount,
home-directory mount, external target, or automatic training.

```bash
docker compose build
docker compose config --quiet
docker compose run --rm init
docker compose up -d api worker frontend
docker compose ps
```

Expected endpoints:

- `http://127.0.0.1:8000/health`
- `http://127.0.0.1:8000/docs`
- `http://127.0.0.1:8501/_stcore/health`
- `http://127.0.0.1:8501`

`init` is idempotent and does not train, activate, ingest, create a case, or
record feedback. `api` is one local process. `worker` is one SQLite writer with
Phase 11 lease/heartbeat semantics. `frontend` calls `http://api:8000` on the
dedicated network and never opens the database. The bridge is not declared
`internal` because that setting prevents published loopback ports from being
reachable in supported Docker environments. Compose does not provide an egress
firewall; AegisHunt runtime workflows remain offline and do not contact an
external target.

Run a demo explicitly:

```bash
docker compose exec api aegishunt demo run \
  --sample-id phase14-attack-like-pcap \
  --actor docker-analyst \
  --reason "explicit controlled Docker demonstration" \
  --confirm
```

Restart persistence:

```bash
docker compose restart api worker frontend
docker compose exec api aegishunt runtime jobs list
```

Stop without deleting data:

```bash
docker compose down
```

After reviewing that no evidence is needed, reset the local demo:

```bash
docker compose down --volumes
```

The image installs a wheel rather than editable source and runs as UID 10001.
Its root filesystem is read-only. A pinned patch-level image tag is used, not
an immutable digest; this residual supply-chain risk is recorded in the
[Threat Model](threat_model.md). Compose is not a production isolation,
authentication, high-availability, or multi-node design.
