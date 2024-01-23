FROM node:18.19-bookworm
EXPOSE 80

WORKDIR /opt/app
COPY package*.json ./

ENTRYPOINT npm install && npm rebuild node-sass && npm run develop

