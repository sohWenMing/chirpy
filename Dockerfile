FROM debian:stable-slim
WORKDIR /usr/local/app
COPY ./chirpy /usr/local/app
COPY ./.env /usr/local/app
WORKDIR /usr/local/app/assets
COPY ./assets /usr/local/app/assets
WORKDIR /usr/local/app
