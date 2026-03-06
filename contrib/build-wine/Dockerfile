FROM debian:trixie@sha256:13f29b6806e531c3ff3b565bb6eed73f2132506c8c9d41bb996065ca20fb27f2

# need ca-certificates before using snapshot packages
RUN apt update -qq > /dev/null && apt install -qq --yes --no-install-recommends \
    ca-certificates

# pin the distro packages.
COPY apt.sources.list /etc/apt/sources.list
COPY apt.preferences /etc/apt/preferences.d/snapshot

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386 && \
    apt-get update -q && \
    apt-get install -qy --allow-downgrades \
        lsb-release \
        wget \
        gnupg2 \
        dirmngr \
        python3 \
        git \
        p7zip-full \
        make \
        cmake \
        pkgconf \
        mingw-w64 \
        mingw-w64-tools \
        autotools-dev \
        autoconf \
        autopoint \
        libtool \
        gettext \
        sudo \
        nsis \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

RUN DEBIAN_CODENAME=$(lsb_release --codename --short) && \
    WINEVERSION="11.0.0.0~${DEBIAN_CODENAME}-1" && \
    wget -nc https://dl.winehq.org/wine-builds/winehq.key && \
        echo "d965d646defe94b3dfba6d5b4406900ac6c81065428bf9d9303ad7a72ee8d1b8 winehq.key" | sha256sum -c - && \
        cat winehq.key | gpg --dearmor -o /etc/apt/keyrings/winehq.gpg && \
        echo deb [signed-by=/etc/apt/keyrings/winehq.gpg] https://dl.winehq.org/wine-builds/debian/ ${DEBIAN_CODENAME} main >> /etc/apt/sources.list.d/winehq.list && \
        rm winehq.key && \
    apt-get update -q && \
    apt-get install -qy --allow-downgrades \
        wine-stable-amd64:amd64=${WINEVERSION} \
        wine-stable-i386:i386=${WINEVERSION} \
        wine-stable:amd64=${WINEVERSION} \
        winehq-stable:amd64=${WINEVERSION} \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

# create new user to avoid using root; but with sudo access and no password for convenience.
ARG UID=1000
RUN if [ "$UID" != "0" ] ; then useradd --uid $UID --create-home --shell /bin/bash "user" ; fi
RUN usermod -append --groups sudo $(id -nu $UID || echo "user")
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
RUN HOME_DIR=$(getent passwd $UID | cut -d: -f6)
ENV WORK_DIR="${HOME_DIR}/wspace" \
    PATH="${HOME_DIR}/.local/bin:${PATH}"
WORKDIR ${WORK_DIR}
RUN chown --recursive ${UID} ${WORK_DIR}
RUN chown ${UID} /opt
USER ${UID}

RUN mkdir --parents "/opt/wine64/drive_c/electrum"
