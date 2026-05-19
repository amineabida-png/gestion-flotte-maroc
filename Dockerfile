FROM node:20-bullseye-slim

RUN apt-get update && \
    apt-get install -y python3 make g++ && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/package*.json ./
RUN npm install --build-from-source
COPY backend/ ./
COPY frontend/ ./frontend/

RUN mkdir -p /app/data

EXPOSE 3000
CMD ["node", "server.js"]
