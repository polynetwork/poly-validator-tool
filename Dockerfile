FROM debian:bullseye-20230703-slim
RUN apt-get update && apt-get install -y git unzip wget curl build-essential
RUN curl -L https://golang.org/dl/go1.20.linux-`dpkg --print-architecture`.tar.gz | tar -C /usr/local -xzf -

WORKDIR /workspace

ARG commit=main

RUN ln -s /usr/local/go/bin/go /usr/bin/go
RUN git clone https://github.com/polynetwork/poly-validator-tool.git  && \
    cd poly-validator-tool && git checkout ${commit} && go build