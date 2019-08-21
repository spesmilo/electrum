FROM ubuntu:18.04@sha256:5f4bdc3467537cbbe563e80db2c3ec95d548a9145d64453b06939c4592d67b6d

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

ARG token
ENV GITHUB_RELEASE_ACCESS_TOKEN=$token
ARG repository
ENV GITHUB_RELEASE_REPOSITORY=$repository
ARG commit
ENV GITHUB_RELEASE_COMMIT=$commit
ARG tag
ENV GITHUB_RELEASE_TAG=$tag

WORKDIR /opt/wine64/drive_c/electrum

RUN dpkg --add-architecture i386 && \
    apt-get update -q && \
    apt-get install git -y && \
    git clone https://github.com/commerceblock/cb-client-wallet.git . && \
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
        pyqt5-dev-tools \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean && \
    go get github.com/google/go-github/github && \
    go get github.com/oleiade/reflections && \
    go get golang.org/x/oauth2 && \
    pyrcc5 icons.qrc -o electrum/gui/qt/icons_rc.py && \
    git clone https://github.com/spesmilo/electrum-locale /tmp/electrum-build/electrum-locale && \
    cp -r /tmp/electrum-build/electrum-locale/locale/ electrum/

WORKDIR /opt/wine64/drive_c/electrum/contrib/build-wine

RUN ./build.sh && ./release.sh
