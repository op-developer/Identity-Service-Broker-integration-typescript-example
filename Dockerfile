FROM node:14.16-buster
EXPOSE 80

WORKDIR /opt/app
COPY package*.json ./

ENTRYPOINT npm install && npm rebuild node-sass && npm run develop

