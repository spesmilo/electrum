FROM ubuntu:16.04@sha256:97b54e5692c27072234ff958a7442dde4266af21e7b688e7fca5dc5acc8ed7d9

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

RUN apt-get update -q && \
    apt-get install -qy \
        git=1:2.7.4-0ubuntu1.6 \
        wget=1.17.1-1ubuntu1.5 \
        make=4.1-6 \
        autotools-dev=20150820.1 \
        autoconf=2.69-9 \
        libtool=2.4.6-0.1 \
        xz-utils=5.1.1alpha+20120614-2ubuntu2 \
        libssl-dev=1.0.2g-1ubuntu4.15 \
        zlib1g-dev=1:1.2.8.dfsg-2ubuntu4.1 \
        libffi-dev=3.2.1-4 \
        libncurses5-dev=6.0+20160213-1ubuntu1 \
        libsqlite3-dev=3.11.0-1ubuntu1.2 \
        libusb-1.0-0-dev=2:1.0.20-1 \
        libudev-dev=229-4ubuntu21.22 \
        gettext=0.19.7-2ubuntu3.1 \
        libzbar0=0.10+doc-10ubuntu1  \
        libdbus-1-3=1.10.6-1ubuntu3.4 \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean
