FROM node:18.17.1

WORKDIR /usr/src/app

COPY package.json /usr/src/app/package.json
COPY package-lock.json /usr/src/app/package-lock.json

RUN npm install

# Rebuild bcrypt for the container's environment
RUN npm rebuild bcrypt --build-from-source

COPY . /usr/src/app

RUN npx prisma generate

RUN npm run build

CMD ["npm", "start"]
