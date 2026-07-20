FROM node:22-alpine

WORKDIR /app

# 의존성 먼저 복사 (캐시 최적화)
COPY package*.json ./
RUN npm ci --omit=dev

# 소스 복사
COPY server.js ./
COPY public/ ./public/

EXPOSE 3000

CMD ["node", "server.js"]
