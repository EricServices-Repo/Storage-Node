FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.js ./
ENV NODE_ENV=production
EXPOSE 80 3901
CMD ["node", "server.js"]
