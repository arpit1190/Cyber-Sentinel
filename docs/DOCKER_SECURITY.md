# Cyber Sentinel — Docker Container Security & Hardening Guide

## 1. Overview & Security Architecture

Cyber Sentinel containers are built with defense-in-depth principles:
- **Zero Privileged Execution**: All processes execute under non-root service accounts (`node` in backend, `nginx` in frontend).
- **Multi-Stage Build Isolation**: Build tools (e.g. GCC, Python, package managers) are confined to the `builder` stage, ensuring minimal attack surface in production runtime layers.
- **Least Privilege Filesystem**: The root filesystem is protected; only `/app/src/data` is writable.
- **Strict Network Isolation**: Containers communicate through private Docker bridge networks (`sentinel-net`).
- **No Hardcoded Secrets**: Secrets and tokens (`JWT_SECRET`, `METRICS_TOKEN`, `DATABASE_URL`) are passed strictly through environment variables.
- **Native Health Probes**: Both containers define native healthchecks verifying service readiness before traffic routing.
- **Signal Handling**: Containers declare `STOPSIGNAL SIGTERM` and handle graceful termination with database pool teardown.

---

## 2. Dockerfile Hardening Matrix

| Security Layer | Backend (`backend/Dockerfile`) | Frontend (`frontend/Dockerfile`) |
| :--- | :--- | :--- |
| **Base Image** | `node:20-alpine` (Minimal footprint) | `nginxinc/nginx-unprivileged:alpine` |
| **User Account** | `USER node` (UID 1000) | `USER nginx` (UID 101) |
| **Port Configuration** | `5000` (Unprivileged) | `8080` (Unprivileged) |
| **Multi-Stage** | Builder (native tools) $\to$ Runner (pure runtime) | Builder (Vite build) $\to$ Runner (Nginx static) |
| **Healthcheck** | `GET /health` probe (30s interval, 5s timeout) | `wget --spider http://localhost:8080/` |
| **Signal Handling** | `STOPSIGNAL SIGTERM` (5s teardown window) | `STOPSIGNAL SIGTERM` |
| **Security Headers** | Helmet middleware (CSP, HSTS, frameguard) | Nginx proxy headers (X-Frame-Options, nosniff, CSP) |

---

## 3. Development vs Production Orchestration

### Production Deployment (`docker-compose.yml`)
Runs hardened production images, non-root users, security options (`no-new-privileges:true`), and explicit healthcheck dependency ordering:
```bash
# Start production stack
docker compose up -d --build

# View container status and health
docker compose ps

# Check logs
docker compose logs -f
```

### Local Development (`docker-compose.dev.yml`)
Enables live reload bind mounts, nodemon, and Vite dev server:
```bash
# Start development stack
docker compose -f docker-compose.dev.yml up --build
```

---

## 4. Verification & Hardening Checklist

- [x] Multi-stage build separates build tools from runtime.
- [x] All images run as non-root unprivileged users.
- [x] Zero exposed secrets or hardcoded passwords in Dockerfiles/compose.
- [x] Native health checks configured and tested on `/health`.
- [x] Proper termination signal handling (`SIGTERM` graceful shutdown).
- [x] `.dockerignore` prevents accidental leaking of `.env`, `node_modules`, or local tests.
