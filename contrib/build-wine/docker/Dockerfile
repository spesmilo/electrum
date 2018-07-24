FROM ubuntu:18.04@sha256:5f4bdc3467537cbbe563e80db2c3ec95d548a9145d64453b06939c4592d67b6d

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

RUN dpkg --add-architecture i386 && \
    apt-get update -q && \
    apt-get install -qy \
        wget=1.19.4-1ubuntu2.1 \
        gnupg2=2.2.4-1ubuntu1.1 \
        dirmngr=2.2.4-1ubuntu1.1 \
        software-properties-common=0.96.24.32.4 \
        && \
    wget -nc https://dl.winehq.org/wine-builds/Release.key && \
    apt-key add Release.key && \
    apt-add-repository https://dl.winehq.org/wine-builds/ubuntu/ && \
    apt-get update -q && \
    apt-get install -qy \
        wine-stable-amd64:amd64=3.0.1~bionic \
        wine-stable-i386:i386=3.0.1~bionic \
        wine-stable:amd64=3.0.1~bionic \
        winehq-stable:amd64=3.0.1~bionic \
        git=1:2.17.1-1ubuntu0.1 \
        p7zip-full=16.02+dfsg-6 \
        make=4.1-9.1ubuntu1 \
        mingw-w64=5.0.3-1 \
        autotools-dev=20180224.1 \
        autoconf=2.69-11 \
        libtool=2.4.6-2 \
        gettext=0.19.8.1-6 \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean
