# Note: we deliberately use an old Ubuntu LTS as base image.
# from https://docs.appimage.org/introduction/concepts.html :
# "[AppImages] should be built on the oldest possible system, allowing them to run on newer system[s]"
FROM ubuntu:16.04@sha256:a4fc0c40360ff2224db3a483e5d80e9164fe3fdce2a8439d2686270643974632

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -q && \
    apt-get install -qy \
        git=1:2.7.4-0ubuntu1.10 \
        wget=1.17.1-1ubuntu1.5 \
        make=4.1-6 \
        autotools-dev=20150820.1 \
        autoconf=2.69-9 \
        libtool=2.4.6-0.1 \
        xz-utils=5.1.1alpha+20120614-2ubuntu2 \
        libssl-dev=1.0.2g-1ubuntu4.19 \
        libssl1.0.0=1.0.2g-1ubuntu4.19 \
        openssl=1.0.2g-1ubuntu4.19 \
        zlib1g-dev=1:1.2.8.dfsg-2ubuntu4.3 \
        libffi-dev=3.2.1-4 \
        libncurses5-dev=6.0+20160213-1ubuntu1 \
        libsqlite3-dev=3.11.0-1ubuntu1.5 \
        libusb-1.0-0-dev=2:1.0.20-1 \
        libudev-dev=229-4ubuntu21.31 \
        gettext=0.19.7-2ubuntu3.1 \
        libzbar0=0.10+doc-10ubuntu1  \
        libdbus-1-3=1.10.6-1ubuntu3.6 \
        libxkbcommon-x11-0=0.5.0-1ubuntu2.1 \
        libxcb1=1.11.1-1ubuntu1 \
        libxcb-xinerama0=1.11.1-1ubuntu1 \
        libxcb-randr0=1.11.1-1ubuntu1 \
        libxcb-render0=1.11.1-1ubuntu1 \
        libxcb-shm0=1.11.1-1ubuntu1 \
        libxcb-shape0=1.11.1-1ubuntu1 \
        libxcb-sync1=1.11.1-1ubuntu1 \
        libxcb-xfixes0=1.11.1-1ubuntu1 \
        libxcb-xkb1=1.11.1-1ubuntu1 \
        libxcb-icccm4=0.4.1-1ubuntu1 \
        libxcb-image0=0.4.0-1build1 \
        libxcb-keysyms1=0.4.0-1 \
        libxcb-util1=0.4.0-0ubuntu3 \
        libxcb-render-util0=0.3.9-1 \
        libx11-xcb1=2:1.6.3-1ubuntu2.2 \
        libc6-dev=2.23-0ubuntu11.3 \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean
