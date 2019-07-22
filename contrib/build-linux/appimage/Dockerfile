FROM ubuntu:14.04@sha256:cac55e5d97fad634d954d00a5c2a56d80576a08dcc01036011f26b88263f1578

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

RUN apt-get update -q && \
    apt-get install -qy \
        git=1:1.9.1-1ubuntu0.10 \
        wget=1.15-1ubuntu1.14.04.5 \
        make=3.81-8.2ubuntu3 \
        autotools-dev=20130810.1 \
        autoconf=2.69-6 \
        libtool=2.4.2-1.7ubuntu1 \
        xz-utils=5.1.1alpha+20120614-2ubuntu2 \
        libssl-dev=1.0.1f-1ubuntu2.27 \
        zlib1g-dev=1:1.2.8.dfsg-1ubuntu1.1 \
        libffi6=3.1~rc1+r3.0.13-12ubuntu0.2 \
        libffi-dev=3.1~rc1+r3.0.13-12ubuntu0.2 \
        libncurses5-dev=5.9+20140118-1ubuntu1 \
        libsqlite3-dev=3.8.2-1ubuntu2.2 \
        libusb-1.0-0-dev=2:1.0.17-1ubuntu2 \
        libudev-dev=204-5ubuntu20.31 \
        gettext=0.18.3.1-1ubuntu3.1 \
        libzbar0=0.10+doc-9build1  \
        libdbus-1-3=1.6.18-0ubuntu4.5 \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean
