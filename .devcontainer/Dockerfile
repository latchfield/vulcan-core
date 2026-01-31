# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Latchfield Technologies http://latchfield.com

FROM mcr.microsoft.com/devcontainers/base:2.1-trixie

# Configure apt for caching and non-interactive use and enable additional repos
ARG DEBIAN_FRONTEND=noninteractive
RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache &&\
    sudo sed -i 's/^Components: main$/Components: main contrib non-free non-free-firmware/g' /etc/apt/sources.list.d/debian.sources

# Update and install core dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    curl --proto '=https' --tlsv1.2 -LsSf 'https://packages.doppler.com/public/cli/gpg.DE2A7741A397C129.key' | gpg --dearmor -o /usr/share/keyrings/doppler-archive-keyring.gpg &&\
    echo "deb [signed-by=/usr/share/keyrings/doppler-archive-keyring.gpg] https://packages.doppler.com/public/cli/deb/debian any-version main" > /etc/apt/sources.list.d/doppler-cli.list &&\
    apt-get update &&\
    apt-get upgrade -y &&\
    apt-get -y install --no-install-recommends socat cron fish pipx doppler

# Create update cron job for security updates. On Debian updating all should be relatively safe.
RUN echo "15 * * * * apt-get update && apt upgrade -y" | crontab -

# Install Nektos Act
RUN wget https://github.com/nektos/act/releases/download/v0.2.84/act_Linux_x86_64.tar.gz -O /tmp/act_linux.tar.gz
RUN tar -xzf /tmp/act_linux.tar.gz -C /usr/bin act