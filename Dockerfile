# SPDX-FileCopyrightText: Copyright 2026 OP Pohjola (https://op.fi)
#
# SPDX-License-Identifier: MIT

FROM node:24.11-trixie
EXPOSE 80

WORKDIR /opt/app
COPY package*.json ./

ENTRYPOINT npm install && npm rebuild sass && npm run develop
