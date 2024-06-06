FROM node:20.13-bookworm
EXPOSE 80

WORKDIR /opt/app
COPY package*.json ./

ENTRYPOINT npm install && npm rebuild node-sass && npm run develop

