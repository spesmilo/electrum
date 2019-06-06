FROM ubuntu:18.04@sha256:5f4bdc3467537cbbe563e80db2c3ec95d548a9145d64453b06939c4592d67b6d

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

RUN dpkg --add-architecture i386 && \
    apt-get update -q && \
    apt-get install -qy \
        wget \
        gnupg2 \
        dirmngr \
        software-properties-common \
        && \
    wget -nc https://dl.winehq.org/wine-builds/Release.key && \
    apt-key add Release.key && \
    wget -nc https://dl.winehq.org/wine-builds/winehq.key && \
    apt-key add winehq.key && \
    apt-add-repository https://dl.winehq.org/wine-builds/ubuntu/ && \
    apt-get update -q && \
    apt-get install -qy \
        wine-stable-amd64:amd64=3.0.1~bionic \
        wine-stable-i386:i386=3.0.1~bionic \
        wine-stable:amd64=3.0.1~bionic \
        winehq-stable:amd64=3.0.1~bionic \
        git \
        p7zip-full \
        make \
        mingw-w64 \
        autotools-dev \
        autoconf \
        libtool \
        gettext \
        direnv \
        golang-go \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean && \
    git clone git@github.com:buildkite/github-release.git

ADD . /opt/wine64/drive_c/electrum/

WORKDIR /opt/wine64/drive_c/electrum/contrib/build-wine

RUN ./build.sh && ./release.sh
