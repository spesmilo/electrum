FROM ubuntu:18.04@sha256:2aeed98f2fa91c365730dc5d70d18e95e8d53ad4f1bbf4269c3bb625060383f0

ARG UBUNTU_MIRROR=http://archive.ubuntu.com/ubuntu/

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

# Official WineHQ signing key
# See https://wiki.winehq.org/Ubuntu
# From https://dl.winehq.org/wine-builds/winehq.key
COPY winehq.key /tmp

# Ubuntu 18.04 lacks libfaudio0 needed for Wine 6
# See https://forum.winehq.org/viewtopic.php?f=8&t=32192
# See also https://askubuntu.com/a/1205596
# From https://download.opensuse.org/repositories/Emulators:/Wine:/Debian/xUbuntu_18.04/Release.key
COPY opensuse.key /tmp

RUN echo deb ${UBUNTU_MIRROR} bionic main restricted universe multiverse > /etc/apt/sources.list && \
    echo deb ${UBUNTU_MIRROR} bionic-updates main restricted universe multiverse >> /etc/apt/sources.list && \
    echo deb ${UBUNTU_MIRROR} bionic-backports main restricted universe multiverse >> /etc/apt/sources.list && \
    echo deb ${UBUNTU_MIRROR} bionic-security main restricted universe multiverse >> /etc/apt/sources.list && \
    dpkg --add-architecture i386 && \
    apt-get update -q && \
    apt-get install -qy \
        gnupg2=2.2.4-1ubuntu1.3 \
        software-properties-common=0.96.24.32.14 && \
    echo "78b185fabdb323971d13bd329fefc8038e08559aa51c4996de18db0639a51df6 /tmp/winehq.key" | sha256sum -c - && \
    apt-key add /tmp/winehq.key && \
    echo "6e4ab6a3731a1f66dbdbe036968ccea64da0c423d312e35b9f8209bb1c82a0a7 /tmp/opensuse.key" | sha256sum -c - && \
    apt-key add /tmp/opensuse.key && \
    apt-add-repository https://dl.winehq.org/wine-builds/ubuntu/ && \
    apt-add-repository 'deb https://download.opensuse.org/repositories/Emulators:/Wine:/Debian/xUbuntu_18.04/ ./' && \
    apt-get update -q && \
    apt-get install -qy \
        wget=1.19.4-1ubuntu2.2 \
        git=1:2.17.1-1ubuntu0.7 \
        p7zip-full=16.02+dfsg-6 \
        make=4.1-9.1ubuntu1 \
        autotools-dev=20180224.1 \
        autoconf=2.69-11 \
        libtool=2.4.6-2 \
        gettext=0.19.8.1-6ubuntu0.3 \
        autopoint=0.19.8.1-6ubuntu0.3 \
        mingw-w64=5.0.3-1 \
        mingw-w64-tools=5.0.3-1 \
        win-iconv-mingw-w64-dev=0.0.8-2 \
        wine-stable-amd64:amd64=6.0.0~bionic-1 \
        wine-stable-i386:i386=6.0.0~bionic-1 \
        wine-stable:amd64=6.0.0~bionic-1 \
        winehq-stable:amd64=6.0.0~bionic-1 && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

ARG USER_ID
ARG GROUP_ID

RUN mkdir -p /homedir/wine64/drive_c/electroncash ; chown -R ${USER_ID}:${GROUP_ID} /homedir && ls -al /homedir
