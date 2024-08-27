FROM node:20.16-bookworm
EXPOSE 80

WORKDIR /opt/app
COPY package*.json ./

ENTRYPOINT npm install && npm rebuild sass && npm run develop

