FROM node:20-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci

COPY . .

ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

RUN npm run build

# ── Runtime image ──────────────────────────────────────────────────────────────
FROM node:20-alpine
WORKDIR /app

COPY --from=builder /app/package.json        ./
COPY --from=builder /app/node_modules        ./node_modules
COPY --from=builder /app/.next               ./.next

ENV PORT=3000 NODE_ENV=production
EXPOSE 3000
CMD ["npm", "start"]
