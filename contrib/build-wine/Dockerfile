FROM debian:bookworm@sha256:b37bc259c67238d814516548c17ad912f26c3eed48dd9bb54893eafec8739c89

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
        wget \
        gnupg2 \
        dirmngr \
        python3-software-properties \
        software-properties-common \
        git \
        p7zip-full \
        make \
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
    WINEVERSION="9.0.0.0~${DEBIAN_CODENAME}-1" && \
    wget -nc https://dl.winehq.org/wine-builds/winehq.key && \
        echo "78b185fabdb323971d13bd329fefc8038e08559aa51c4996de18db0639a51df6 winehq.key" | sha256sum -c - && \
        cat winehq.key | gpg --dearmor -o /etc/apt/keyrings/winehq.gpg && \
        echo deb [signed-by=/etc/apt/keyrings/winehq.gpg] https://dl.winehq.org/wine-builds/debian/ ${DEBIAN_CODENAME} main >> /etc/apt/sources.list.d/winehq.list && \
        rm winehq.key && \
    apt-get update -q && \
    apt-get install -qy --allow-downgrades \
        wine-stable-amd64:amd64=${WINEVERSION} \
        wine-stable-i386:i386=${WINEVERSION} \
        wine-stable:amd64=${WINEVERSION} \
        winehq-stable:amd64=${WINEVERSION} \
        libvkd3d1:amd64=1.3~${DEBIAN_CODENAME}-1 \
        libvkd3d1:i386=1.3~${DEBIAN_CODENAME}-1 \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

# create new user to avoid using root; but with sudo access and no password for convenience.
ARG UID=1000
ENV USER="user"
ENV HOME_DIR="/home/${USER}"
ENV WORK_DIR="${HOME_DIR}/wspace" \
    PATH="${HOME_DIR}/.local/bin:${PATH}"
RUN useradd --uid $UID --create-home --shell /bin/bash ${USER}
RUN usermod -append --groups sudo ${USER}
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
WORKDIR ${WORK_DIR}
RUN chown --recursive ${USER} ${WORK_DIR}
RUN chown ${USER} /opt
USER ${USER}

RUN mkdir --parents "/opt/wine64/drive_c/electrum"
