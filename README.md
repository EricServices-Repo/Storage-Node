# Remote storage node (Docker)

This folder ships a small **HTTP storage service** that matches how the main File-Uploader app lays out files: per user under `users/{user_id}/files/` and folder-share ZIPs under `users/{user_id}/fshare_zips/`. The PHP site talks to it with **Bearer authentication** and stores pool settings in MySQL (`storage_servers.remote_api_base_url` / `remote_api_secret`).

## 1. Run the node

```bash
cd 1docker
cp .env.example .env
# Edit .env — set STORAGE_API_SECRET to a long random string
docker compose up -d --build
```

Published ports on the host:

- **80** → **management UI** only (`/`, `/ui/*`). The storage **HTTP API is not served on this port**.
- **3901** → **storage API** (`/v1/*`) for the File-Uploader PHP app and other clients.

Data persists in the named volume `storage_data` (under `/data` in the container).

**Management UI (first use):** open `http://<host>/ui/login` (port **80**). Sign in with the **same value** as `STORAGE_API_SECRET` (this is the Bearer token the PHP app uses on port **3901**). The dashboard includes:

- **Storage status** — **Active**, **Maintenance** (read-only API: GET/HEAD allowed; POST/PUT/DELETE return 503), or **Disabled** (all `/v1/*` return 503, including health). Status is saved under `DATA_ROOT/.file-uploader-node/node_state.json` and overrides `STORAGE_NODE_STATUS` until changed again.
- **Live metrics** — CPU (sampled % and load averages), RAM/swap (from `/proc/meminfo`), network RX/TX totals and estimated throughput (from `/proc/net/dev`), and volume/inode usage for `DATA_ROOT` (refreshed in the browser).
- **Node transfer** — copy every blob to another node’s API (`http(s)://host:port` with no path); optional **delete local** after each successful PUT. You must type `TRANSFER_NODE` to confirm. Put the node in **Maintenance** first so writers stop. Large moves can take a long time; jobs are tracked in memory until the process restarts.
- **Prepare user** — same as `POST /v1/users/:uid/prepare` on the API port.

Health check: `GET /v1/health` with header `Authorization: Bearer <secret>` → JSON including `ok`, `data_root`, and `node_status`. When status is **Disabled**, this returns **503** with `{ ok: false, ... }`, so the default Compose health check marks the container unhealthy—change the probe if you need the container “up” while drained.

## 2. Database migration (main app)

On the server that runs the PHP application:

```bash
mysql … < sql/migration_023_storage_remote_api.sql
```

(or apply the same columns from `sql/schema.sql` on fresh installs).

## 3. Admin UI

1. Open **Admin → Storage**.
2. **Add server** (or edit a pool):
   - **Base path**: keep a valid absolute path for documentation (e.g. `/var/lib/file-uploader/remote-pool-1`). It is **not** used for blob I/O when the remote URL is set.
   - **Remote storage API base URL**: public URL of the **API port (3901)**, e.g. `https://storage.example.com:3901` (no trailing slash). Do **not** use port 80 here—that port is for the management UI only.
   - **Remote API secret**: exactly the same value as `STORAGE_API_SECRET` in `1docker/.env`.
3. Assign users to that pool (empty accounts only, same rules as before).

## 4. Production networking

- Put **HTTPS** in front of the node (reverse proxy or cloud load balancer). The PHP app accepts `http://` for development only; prefer TLS in production.
- Restrict who can reach **port 3901** (API): typically only your **web app servers**. For **port 80** (UI), limit to operators or put the UI behind VPN / SSH tunnel; it uses the same secret as the API for login.
- **Throughput**: every upload/download passes through the web tier to the node; size your network and PHP `max_execution_time` accordingly.

## 5. Limitations (current release)

- **Pool migration jobs** and **one-shot migrate** in Admin do not copy to/from HTTP remote pools (they are blocked with a clear message). Use remote pools for **new** users or manual operations outside this app.
- Chunked uploads still assemble **.part** files on the web server under `uploads/.chunk_resume/{user_id}/`, then the finished object is **PUT** to the node.

## API reference (for operators / custom clients)

All routes require: `Authorization: Bearer <STORAGE_API_SECRET>`.

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/v1/health` | Liveness |
| POST | `/v1/users/:uid/prepare` | Create `files/` and `fshare_zips/` dirs for numeric user id |
| PUT | `/v1/users/:uid/files/:storedName` | Raw body; `Content-Length` required; `storedName` = 32 hex chars |
| GET | `/v1/users/:uid/files/:storedName` | Stream blob |
| HEAD | `/v1/users/:uid/files/:storedName` | Exists + `Content-Length` |
| DELETE | `/v1/users/:uid/files/:storedName` | Remove blob |
| PUT | `/v1/users/:uid/fshare-zips/:name` | ZIP body; name like `….zip` (32 hex + `.zip`) |
| GET / HEAD / DELETE | `/v1/users/:uid/fshare-zips/:name` | Same pattern for share ZIPs |

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `UI_PORT` | `80` | Management UI listen port |
| `API_PORT` | `3901` | Storage API listen port (`PORT` is accepted as an alias for **API_PORT** only) |
| `DATA_ROOT` | `/data` | Root directory for `users/` tree |
| `STORAGE_API_SECRET` | _(required)_ | Bearer token shared with PHP |
| `STORAGE_NODE_STATUS` | `active` | Initial status if no persisted file exists yet (`active` / `maintenance` / `disabled`) |
| `MAX_TRANSFER_OBJECTS` | `200000` | Safety cap for objects walked by UI **Node transfer** |
| `MAX_PUT_BYTES` | 64 GiB | Upper bound for a single PUT body |
