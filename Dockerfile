FROM ubuntu:17.10


RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y wine-development dirmngr gnupg2 wget git gettext p7zip && \
    ln -sf /usr/lib/wine-development/wine64 /usr/local/bin/wine

ENV WINEPREFIX="/opt/wine64" WINEPATH="c:\\mingw32\\bin"

RUN wget -O/tmp/mingw32.7z https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win32/Personal%20Builds/mingw-builds/7.2.0/threads-posix/dwarf/i686-7.2.0-release-posix-dwarf-rt_v5-rev1.7z && \
    bash -c 'sha256sum -c - <<< "8451a013ce317c72edde4c65932d6770dd98910a27714527ac27dc76bd3123f1 /tmp/mingw32.7z"'

ADD . /electrum

RUN cd /electrum/contrib/build-wine && ./build.sh
