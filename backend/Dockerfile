# ==========================================
# Stage 1: Build & Production Dependencies
# ==========================================
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies required for building native modules if needed
RUN apk add --no-cache python3 make g++

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# ==========================================
# Stage 2: Minimal Hardened Runtime
# ==========================================
FROM node:20-alpine AS runner

# Security: Set production environment
ENV NODE_ENV=production
ENV PORT=5000

WORKDIR /app

# Create necessary directories and assign ownership to non-root node user
RUN mkdir -p /app/src/data/quarantine && \
    chown -R node:node /app

# Copy production node_modules from builder
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package*.json ./
COPY --chown=node:node src/ ./src/

# Security: Run as unprivileged user
USER node

# Health check against production endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "require('http').get('http://localhost:' + (process.env.PORT || 5000) + '/health', (r) => {if (r.statusCode !== 200) process.exit(1)}).on('error', () => process.exit(1))"

# Proper termination signal handling
STOPSIGNAL SIGTERM

EXPOSE 5000

CMD ["node", "src/server.js"]
