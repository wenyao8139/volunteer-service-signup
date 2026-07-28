FROM node:22-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY index.js ./
COPY seed.js seed-data.json ./

ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "index.js"]
