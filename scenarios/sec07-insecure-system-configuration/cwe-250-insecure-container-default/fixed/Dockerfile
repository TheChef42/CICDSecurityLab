FROM node:20-bookworm

WORKDIR /app
COPY package.json ./
RUN npm install --ignore-scripts \
    && groupadd --system appgroup \
    && useradd --system --gid appgroup --home-dir /app appuser \
    && chown -R appuser:appgroup /app

USER appuser

CMD ["node", "-e", "console.log('running as non-root user')"]
