FROM node:24.14-trixie
EXPOSE 80

WORKDIR /opt/app
COPY package*.json ./

ENTRYPOINT npm install && npm rebuild sass && npm run develop
