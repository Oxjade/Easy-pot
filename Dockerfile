FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci
COPY src ./src
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production \
    EASYPOT_CONFIG=/etc/easypot/easypot.config.json \
    EASYPOT_DATA_DIR=/var/lib/easypot \
    EASYPOT_ADMIN_HOST=0.0.0.0
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY dashboard ./dashboard
COPY site ./site
COPY rules ./rules
RUN mkdir -p /var/lib/easypot /etc/easypot && chown -R node:node /var/lib/easypot
USER node
EXPOSE 8080 8081 8082
VOLUME ["/var/lib/easypot"]
CMD ["node", "--disable-warning=ExperimentalWarning", "dist/index.js"]
