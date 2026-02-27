# Telewatch Service

Standalone website backend for Frenzy Telewatch rooms.

## Run locally

```bash
cd /root/Frenzynet/telewatch-service
python3 server.py
```

Default bind: `127.0.0.1:9191`

## Environment

- `TELEWATCH_HOST` (default `127.0.0.1`)
- `TELEWATCH_PORT` (default `9191`)
- `TELEWATCH_DB_PATH` (default `/root/Frenzynet/telewatch-service/data/telewatch.db`)
- `TELEWATCH_ROOM_TTL_HOURS` (default `24`)
- `TELEWATCH_PUBLIC_ROOM_PREFIX` (default `WATCH`)
- `TELEWATCH_PUBLIC_ROOM_COUNT` (default `10`)

## Reverse proxy (nginx)

```nginx
location /api/telewatch/ {
  proxy_pass http://127.0.0.1:9191/;
  proxy_http_version 1.1;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

With this route, the web page at `/telewatch/` will call:
- `POST /api/telewatch/api/watch/create`
- `POST /api/telewatch/api/watch/join`
- `GET /api/telewatch/api/watch/state`
- `POST /api/telewatch/api/watch/control`

Homepage public room list:
- `GET /api/telewatch/public-rooms`
