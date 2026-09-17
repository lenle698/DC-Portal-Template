FROM node:20-alpine

WORKDIR /app
COPY . .
RUN npm install --omit=dev

ENV PORT=8080
EXPOSE 8080

CMD ["node", "server.mjs"]
