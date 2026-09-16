# ==========================================
# Stage 1: Build Production Bundle
# ==========================================
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . ./
RUN npm run build

# ==========================================
# Stage 2: Minimal Hardened Nginx Runtime
# ==========================================
FROM nginxinc/nginx-unprivileged:alpine AS runner

# Copy built frontend assets
COPY --from=builder /app/dist /usr/share/nginx/html
COPY --chown=nginx:nginx nginx.conf /etc/nginx/conf.d/default.conf

# Health check
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -q --spider http://localhost:8080/ || exit 1

STOPSIGNAL SIGTERM

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
