# syntax=docker/dockerfile:1.7

# --- Dependencies layer ---
    FROM node:20-alpine AS deps
    WORKDIR /app
    
    # Copy only manifests first for better caching
    COPY package*.json ./
    # If you use pnpm/yarn, swap this for the right install command
    RUN npm ci --omit=dev
    
    # --- Runtime image ---
    FROM node:20-alpine AS runner
    ENV NODE_ENV=production
    WORKDIR /app
    
    # Create and use an unprivileged user
    RUN addgroup -S app && adduser -S app -G app
    
    # Copy installed deps and app source
    COPY --from=deps /app/node_modules ./node_modules
    COPY . .
    
    # Ensure ESM works (your package.json should have: "type": "module")
    # USER must be set after files are copied so ownership is correct
    USER app
    
    # MCP servers speak over stdio; no EXPOSE needed.
    # Keep it simple: run the ESM entrypoint.
    CMD ["node", "index.js"]
