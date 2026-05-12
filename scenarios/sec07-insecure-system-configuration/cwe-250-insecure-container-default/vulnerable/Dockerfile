FROM node:20-bookworm

WORKDIR /app
COPY package.json ./
RUN npm install --ignore-scripts

CMD ["node", "-e", "console.log('running as default user')"]
