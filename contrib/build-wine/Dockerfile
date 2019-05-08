FROM ubuntu:18.04@sha256:5f4bdc3467537cbbe563e80db2c3ec95d548a9145d64453b06939c4592d67b6d

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

RUN dpkg --add-architecture i386 && \
    apt-get update -q && \
    apt-get install -qy \
        wget=1.19.4-1ubuntu2.2 \
        gnupg2=2.2.4-1ubuntu1.2 \
        dirmngr=2.2.4-1ubuntu1.2 \
        python3-software-properties=0.96.24.32.1 \
        software-properties-common=0.96.24.32.1

RUN apt-get update -q && \
        apt-get install -qy \
        git=1:2.17.1-1ubuntu0.4 \
        p7zip-full=16.02+dfsg-6 \
        make=4.1-9.1ubuntu1 \
        mingw-w64=5.0.3-1 \
        autotools-dev=20180224.1 \
        autoconf=2.69-11 \
        libtool=2.4.6-2 \
        gettext=0.19.8.1-6

RUN wget -nc https://dl.winehq.org/wine-builds/Release.key && \
        echo "c51bcb8cc4a12abfbd7c7660eaf90f49674d15e222c262f27e6c96429111b822 Release.key" | sha256sum -c - && \
        apt-key add Release.key && \
    wget -nc https://dl.winehq.org/wine-builds/winehq.key && \
        echo "78b185fabdb323971d13bd329fefc8038e08559aa51c4996de18db0639a51df6 winehq.key" | sha256sum -c - && \
        apt-key add winehq.key && \
    apt-add-repository https://dl.winehq.org/wine-builds/ubuntu/ && \
    apt-get update -q && \
    apt-get install -qy \
        wine-stable-amd64:amd64=4.0~bionic \
        wine-stable-i386:i386=4.0~bionic \
        wine-stable:amd64=4.0~bionic \
        winehq-stable:amd64=4.0~bionic

RUN rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean
