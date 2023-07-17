FROM golang:1.20-bullseye

ARG commit=main

WORKDIR /workspace

COPY . ./

RUN go mod download
RUN go build
