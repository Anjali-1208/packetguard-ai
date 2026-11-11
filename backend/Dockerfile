FROM node:24-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY prisma ./prisma
RUN npx prisma generate
COPY src ./src
ENV NODE_ENV=production DATABASE_URL=file:/data/packetguard.db PORT=5000
RUN mkdir -p /data
EXPOSE 5000
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s CMD node -e "fetch('http://localhost:5000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["sh", "-c", "npx prisma db push --skip-generate && node src/index.js"]
