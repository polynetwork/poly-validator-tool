FROM golang:1.20-bullseye

ARG commit=master

WORKDIR /workspace

COPY . ./

RUN go mod download
RUN go build
