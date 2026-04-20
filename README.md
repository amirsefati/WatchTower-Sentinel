# watchtower-sentinel

Lightweight Go security watcher for Linux servers. It tails the Nginx access log, tracks first-seen client IPs, watches CPU/RAM pressure, inspects suspicious processes, and sends concise Telegram alerts.

## Run

```bash
cp .env.example .env
docker compose up -d --build
```

## Notes

- Mounts host Nginx logs and `/proc` into the container by default.
- Every Telegram message includes `SERVER_LOCATION`, `SERVER_NAME`, hostname, severity, reason, and timestamp.
- Primary health endpoint: `http://127.0.0.1:8081/healthz`
