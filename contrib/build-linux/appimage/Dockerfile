# Note: we deliberately use an old Ubuntu LTS as base image.
# from https://docs.appimage.org/introduction/concepts.html :
# "[AppImages] should be built on the oldest possible system, allowing them to run on newer system[s]"
FROM ubuntu:18.04@sha256:9bc830af2bef73276515a29aa896eedfa7bdf4bdbc5c1063b4c457a4bbb8cd79

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -q && \
    apt-get install -qy \
        git=1:2.17.1-1ubuntu0.9 \
        wget=1.19.4-1ubuntu2.2 \
        make=4.1-9.1ubuntu1 \
        autotools-dev=20180224.1 \
        autoconf=2.69-11 \
        libtool=2.4.6-2 \
        autopoint=0.19.8.1-6ubuntu0.3 \
        xz-utils=5.2.2-1.3 \
        libssl-dev=1.1.1-1ubuntu2.1~18.04.13 \
        libssl1.1=1.1.1-1ubuntu2.1~18.04.13 \
        openssl=1.1.1-1ubuntu2.1~18.04.13 \
        zlib1g-dev=1:1.2.11.dfsg-0ubuntu2 \
        libffi-dev=3.2.1-8 \
        libncurses5-dev=6.1-1ubuntu1.18.04 \
        libncurses5=6.1-1ubuntu1.18.04 \
        libtinfo-dev=6.1-1ubuntu1.18.04 \
        libtinfo5=6.1-1ubuntu1.18.04 \
        libsqlite3-dev=3.22.0-1ubuntu0.4 \
        libusb-1.0-0-dev=2:1.0.21-2 \
        libudev-dev=237-3ubuntu10.53 \
        libudev1=237-3ubuntu10.53 \
        gettext=0.19.8.1-6ubuntu0.3 \
        libzbar0=0.10+doc-10.1build2  \
        libdbus-1-3=1.12.2-1ubuntu1.2 \
        libxkbcommon0=0.8.0-1ubuntu0.1 \
        libxkbcommon-x11-0=0.8.0-1ubuntu0.1 \
        libxcb1=1.13-1 \
        libxcb-xinerama0=1.13-1 \
        libxcb-randr0=1.13-1 \
        libxcb-render0=1.13-1 \
        libxcb-shm0=1.13-1 \
        libxcb-shape0=1.13-1 \
        libxcb-sync1=1.13-1 \
        libxcb-xfixes0=1.13-1 \
        libxcb-xkb1=1.13-1 \
        libxcb-icccm4=0.4.1-1ubuntu1 \
        libxcb-image0=0.4.0-1build1 \
        libxcb-keysyms1=0.4.0-1 \
        libxcb-util1=0.4.0-0ubuntu3 \
        libxcb-render-util0=0.3.9-1 \
        libx11-xcb1=2:1.6.4-3ubuntu0.4 \
        libc6-dev=2.27-3ubuntu1.4 \
        libc6=2.27-3ubuntu1.4 \
        libc-dev-bin=2.27-3ubuntu1.4 \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean
