# Bim Pulse — zero-dependency Node server; Leaflet is the only package (the map).
FROM node:22-alpine
WORKDIR /app
RUN echo '{"type":"module","private":true}' > package.json && npm install --no-audit --no-fund --ignore-scripts leaflet@1.9.4
COPY apps/bimpulse/server.js ./server.js
COPY apps/bimpulse/public ./public
# Render mounts the disk at /data owned by root: fix ownership at start, then drop to the unprivileged user.
RUN apk add --no-cache su-exec && mkdir -p /data
ENV HOST=0.0.0.0 PORT=8790 NODE_ENV=production DATA_DIR=/data
EXPOSE 8790
HEALTHCHECK CMD wget -qO- http://127.0.0.1:8790/healthz || exit 1
CMD ["sh", "-c", "chown -R node:node /data && exec su-exec node node server.js"]
