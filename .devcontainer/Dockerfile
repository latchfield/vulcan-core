# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

# https://hub.docker.com/r/microsoft/devcontainers-python
FROM mcr.microsoft.com/devcontainers/python:3.10-bookworm

# Install unattended-upgrades and configure for hourly security-only updates
# https://askubuntu.com/a/412
RUN apt-get update &&\
    apt-get -y install --no-install-recommends unattended-upgrades cron
RUN sed -i '/origin=Debian,codename=${distro_codename},label=Debian\"/s/^/\/\//' /etc/apt/apt.conf.d/50unattended-upgrades

# Create update cron job. May also be set by apt-daily.timer, needs investigation https://askubuntu.com/a/1340016
RUN echo "15 * * * * unattended-upgrade" | crontab -

# Apply security updates
RUN unattended-upgrade -v

# Install poetry
RUN pipx install poetry==2.1.2
RUN pipx inject poetry poetry-plugin-up==0.9.0

# Install Nektos Act
RUN wget https://github.com/nektos/act/releases/download/v0.2.75/act_Linux_x86_64.tar.gz -O /tmp/act_linux.tar.gz
RUN tar -xzf /tmp/act_linux.tar.gz -C /usr/bin act

# Install Doppler CLI
RUN apt-get update && apt-get install -y apt-transport-https ca-certificates curl gnupg
RUN curl -sLf --retry 3 --tlsv1.2 --proto "=https" 'https://packages.doppler.com/public/cli/gpg.DE2A7741A397C129.key' | gpg --dearmor -o /usr/share/keyrings/doppler-archive-keyring.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/doppler-archive-keyring.gpg] https://packages.doppler.com/public/cli/deb/debian any-version main" | tee /etc/apt/sources.list.d/doppler-cli.list
RUN apt-get update && apt-get install doppler