FROM node:16.19-bullseye
EXPOSE 80

WORKDIR /opt/app
COPY package*.json ./

ENTRYPOINT npm install && npm rebuild node-sass && npm run develop

