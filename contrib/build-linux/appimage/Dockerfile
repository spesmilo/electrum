FROM ubuntu:14.04@sha256:cac55e5d97fad634d954d00a5c2a56d80576a08dcc01036011f26b88263f1578

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

RUN apt-get update -q && \
    apt-get install -qy \
        git \
        wget \
        make \
        autotools-dev \
        autoconf \
        libtool \
        xz-utils \
        libssl-dev \
        zlib1g-dev \
        libffi6 \
        libffi-dev \
        libusb-1.0-0-dev \
        libudev-dev \
        gettext \
        libzbar0  \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean
