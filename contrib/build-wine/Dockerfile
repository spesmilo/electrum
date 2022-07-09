FROM ubuntu:20.04@sha256:c95a8e48bf88e9849f3e0f723d9f49fa12c5a00cfc6e60d2bc99d87555295e4c

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386 && \
    apt-get update -q && \
    apt-get install -qy \
        wget=1.20.3-1ubuntu1 \
        gnupg2=2.2.19-3ubuntu2.2 \
        dirmngr=2.2.19-3ubuntu2.2 \
        python3-software-properties=0.98.9.2 \
        software-properties-common=0.98.9.2 \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

RUN apt-get update -q && \
    apt-get install -qy \
        git=1:2.25.1-1ubuntu3 \
        p7zip-full=16.02+dfsg-7build1 \
        make=4.2.1-1.2 \
        mingw-w64=7.0.0-2 \
        mingw-w64-tools=7.0.0-2 \
        win-iconv-mingw-w64-dev=0.0.8-3 \
        autotools-dev=20180224.1 \
        autoconf=2.69-11.1 \
        autopoint=0.19.8.1-10build1 \
        libtool=2.4.6-14 \
        gettext=0.19.8.1-10build1 \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

RUN wget -nc https://dl.winehq.org/wine-builds/Release.key && \
        echo "c51bcb8cc4a12abfbd7c7660eaf90f49674d15e222c262f27e6c96429111b822 Release.key" | sha256sum -c - && \
        apt-key add Release.key && \
        rm Release.key && \
    wget -nc https://dl.winehq.org/wine-builds/winehq.key && \
        echo "78b185fabdb323971d13bd329fefc8038e08559aa51c4996de18db0639a51df6 winehq.key" | sha256sum -c - && \
        apt-key add winehq.key && \
        rm winehq.key && \
    apt-add-repository https://dl.winehq.org/wine-builds/ubuntu/ && \
    apt-get update -q && \
    apt-get install -qy \
        wine-stable-amd64:amd64=7.0.0.0~focal-1 \
        wine-stable-i386:i386=7.0.0.0~focal-1 \
        wine-stable:amd64=7.0.0.0~focal-1 \
        winehq-stable:amd64=7.0.0.0~focal-1 \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

# create new user to avoid using root; but with sudo access and no password for convenience.
ENV USER="user"
ENV HOME_DIR="/home/${USER}"
ENV WORK_DIR="${HOME_DIR}/wspace" \
    PATH="${HOME_DIR}/.local/bin:${PATH}"
RUN useradd --create-home --shell /bin/bash ${USER}
RUN usermod -append --groups sudo ${USER}
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
WORKDIR ${WORK_DIR}
RUN chown --recursive ${USER} ${WORK_DIR}
RUN chown ${USER} /opt
USER ${USER}

RUN mkdir --parents "/opt/wine64/drive_c/electrum"
