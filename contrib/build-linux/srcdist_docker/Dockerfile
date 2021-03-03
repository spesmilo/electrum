FROM ubuntu:18.04@sha256:5f4bdc3467537cbbe563e80db2c3ec95d548a9145d64453b06939c4592d67b6d

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

RUN apt-get update -q && \
    apt-get install -qy \
        git \
        wget \
        make \
        autotools-dev \
        autoconf \
        autopoint \
        libtool \
        xz-utils \
        libssl-dev \
        zlib1g-dev \
        libffi6 \
        libffi-dev \
        libncurses5-dev \
        libsqlite3-dev \
        libusb-1.0-0-dev \
        libudev-dev \
        gettext \
        libzbar0 \
        faketime \
        python3 \
        python3-pip \
        python3-venv \
        pkg-config \
        libjpeg-dev \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean
