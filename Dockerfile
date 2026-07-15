FROM mcr.microsoft.com/playwright:v1.47.0-jammy

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

ENV PORT=80
EXPOSE 80

CMD ["node", "server.js"]
