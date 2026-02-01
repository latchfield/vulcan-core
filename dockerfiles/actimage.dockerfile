# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Latchfield Technologies http://latchfield.com
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update && apt-get install -y ca-certificates curl sudo gnupg pipx jq build-essential

RUN useradd -m -d /home/runner -s /bin/bash runner &&\
    echo "runner ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/runner

ENV NODE_MAJOR=24
RUN mkdir -p /etc/apt/keyrings
RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
RUN echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
RUN apt update && apt install -y nodejs

USER runner
