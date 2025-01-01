# Note: we deliberately use an old Debian stable as base image.
# from https://docs.appimage.org/introduction/concepts.html :
# "[AppImages] should be built on the oldest possible system, allowing them to run on newer system[s]"

FROM debian:buster@sha256:233c3bbc892229c82da7231980d50adceba4db56a08c0b7053a4852782703459

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

# need ca-certificates before using snapshot packages
RUN apt update -qq > /dev/null && apt install -qq --yes --no-install-recommends \
    ca-certificates

# pin the distro packages
COPY apt.sources.list /etc/apt/sources.list
COPY apt.preferences /etc/apt/preferences.d/snapshot

RUN apt-get update -q && \
    apt-get install -qy --allow-downgrades \
        sudo \
        git \
        wget \
        make \
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
        libxcb-util0 \
        #libxcb-util1 \
        libxcb-render-util0 \
        libxcb-cursor0 \
        libx11-xcb1 \
        libc6-dev \
        libc6 \
        libc-dev-bin \
        libv4l-dev \
        libjpeg62-turbo-dev \
        libx11-dev \
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
USER ${USER}
