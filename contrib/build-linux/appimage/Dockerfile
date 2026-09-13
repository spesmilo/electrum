# Note: we deliberately use an old Debian stable as base image.
# from https://docs.appimage.org/introduction/concepts.html :
# "[AppImages] should be built on the oldest possible system, allowing them to run on newer system[s]"

FROM debian:bullseye@sha256:cf48c31af360e1c0a0aedd33aae4d928b68c2cdf093f1612650eb1ff434d1c34

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

# pin the distro packages
COPY apt.sources.list /etc/apt/sources.list
COPY apt.preferences /etc/apt/preferences.d/snapshot

# fetch ca-certificates via http first so the snapshot packages below can be fetched via https
# FIXME: could be simplified back to the below when bumping the base image:
# https://github.com/spesmilo/electrum/blob/722f70238d8f719c0fa64940c5dd9c892782f8da/contrib/build-linux/appimage/Dockerfile#L10-L12
RUN sed -e 's#https://#http://#' /etc/apt/sources.list > /tmp/sources.list.bootstrap && \
    apt-get -o Dir::Etc::SourceList=/tmp/sources.list.bootstrap update -q && \
    apt-get -o Dir::Etc::SourceList=/tmp/sources.list.bootstrap install -qy --allow-downgrades --no-install-recommends \
        ca-certificates \
        && \
    rm -f /tmp/sources.list.bootstrap && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update -q && \
    apt-get install -qy --allow-downgrades \
        sudo \
        git \
        wget \
        python3 \
        make \
        cmake \
        clang-16 \
        autotools-dev \
        autoconf \
        libtool \
        autopoint \
        pkg-config \
        xz-utils \
        libssl-dev \
        libssl1.1 \
        openssl \
        zlib1g-dev \
        libffi-dev \
        libncurses5-dev \
        libncurses5 \
        libtinfo-dev \
        libtinfo5 \
        libsqlite3-dev \
        libusb-1.0-0-dev \
        libudev-dev \
        libudev1 \
        gettext \
        libdbus-1-3 \
        xutils-dev \
        libxkbcommon0 \
        libxkbcommon-x11-0 \
        libxcb1-dev \
        libxcb-xinerama0 \
        libxcb-randr0 \
        libxcb-render0 \
        libxcb-shm0 \
        libxcb-shape0 \
        libxcb-sync1 \
        libxcb-xfixes0 \
        libxcb-xkb1 \
        libxcb-icccm4 \
        libxcb-image0 \
        libxcb-keysyms1 \
        libxcb-util1 \
        libxcb-render-util0 \
        libxcb-cursor0 \
        libx11-xcb1 \
        libc6-dev \
        libc6 \
        libc-dev-bin \
        libx11-dev \
        libegl1 \
        libgl1 \
        libpulse0 \
        libxrandr2 \
        desktop-file-utils \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

# create new user to avoid using root; but with sudo access and no password for convenience.
ARG UID=1000
RUN useradd -u "$UID" -m -s /usr/bin/bash -d /home/user user
RUN usermod -aG sudo user
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
ENV HOME_DIR=/home/user
ENV WORK_DIR="${HOME_DIR}/wspace"
ENV PATH="${HOME_DIR}/.local/bin:${PATH}"
WORKDIR ${WORK_DIR}
RUN chown -R user ${WORK_DIR}
USER user
