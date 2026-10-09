FROM node:26-slim@sha256:930557a230abacbc3f4fd9b8648abf8f4bee1e17cb72195dcdfb2f709bc85b33 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM deps AS dev
COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

FROM deps AS build
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.31-alpine@sha256:b9241c6e7b8e9a862f129d8d4199ab64b10390949a78bdd5603379b32c844083 AS runtime
# Security fixes published since the pinned base image (the release scan fails on any fixable
# HIGH or CRITICAL vulnerability); the image runs as its unprivileged nginx user again after.
USER root
RUN apk upgrade --no-cache
USER 101
COPY --from=build /app/dist /usr/share/nginx/html
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --chmod=0755 docker/15-ansideck-real-ip.sh /docker-entrypoint.d/15-ansideck-real-ip.sh
# The license travels with the image (the named build context "repo" is the repository root:
# docker-compose.yml, and build-contexts in the workflows).
COPY --from=repo LICENSE /usr/share/licenses/ansideck/LICENSE
LABEL org.opencontainers.image.title="AnsiDeck frontend" \
      org.opencontainers.image.description="AnsiDeck web UI, served by nginx" \
      org.opencontainers.image.source="https://github.com/HoneyBearTech/AnsiDeck" \
      org.opencontainers.image.url="https://github.com/HoneyBearTech/AnsiDeck" \
      org.opencontainers.image.documentation="https://github.com/HoneyBearTech/AnsiDeck/tree/main/docs" \
      org.opencontainers.image.licenses="MIT"
EXPOSE 8080
