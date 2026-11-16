# One image serves every service; SERVICE selects which one a container runs.
FROM node:24-alpine
WORKDIR /app

COPY package.json package-lock.json ./
COPY packages/common/package.json packages/common/
COPY services/auth-service/package.json services/auth-service/
COPY services/gateway/package.json services/gateway/
COPY services/resource-service/package.json services/resource-service/
COPY services/audit-service/package.json services/audit-service/
RUN npm ci --omit=dev

COPY packages packages
COPY services services

USER node
CMD ["sh", "-c", "exec node --import tsx services/$SERVICE/src/main.ts"]
