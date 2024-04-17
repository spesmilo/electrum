# based on https://github.com/kivy/python-for-android/blob/master/Dockerfile

FROM debian:bookworm@sha256:d568e251e460295a8743e9d5ef7de673c5a8f9027db11f4e666e96fb5bed708e

ENV DEBIAN_FRONTEND=noninteractive

ENV ANDROID_HOME="/opt/android"

# need ca-certificates before using snapshot packages
RUN apt update -qq > /dev/null && apt install -qq --yes --no-install-recommends \
    ca-certificates

# pin the distro packages.
COPY contrib/android/apt.sources.list /etc/apt/sources.list
COPY contrib/android/apt.preferences /etc/apt/preferences.d/snapshot

# configure locale
RUN apt update -qq > /dev/null && apt install -qq --yes --no-install-recommends --allow-downgrades \
    locales && \
    locale-gen en_US.UTF-8
ENV LANG="en_US.UTF-8" \
    LANGUAGE="en_US.UTF-8" \
    LC_ALL="en_US.UTF-8"

RUN apt -y update -qq \
    && apt -y install -qq --no-install-recommends --allow-downgrades \
    curl \
    unzip \
    ca-certificates \
    && apt -y autoremove


ENV ANDROID_NDK_HOME="${ANDROID_HOME}/android-ndk"
ENV ANDROID_NDK_VERSION="23b"
ENV ANDROID_NDK_HASH="c6e97f9c8cfe5b7be0a9e6c15af8e7a179475b7ded23e2d1c1fa0945d6fb4382"
ENV ANDROID_NDK_HOME_V="${ANDROID_NDK_HOME}-r${ANDROID_NDK_VERSION}"

# get the latest version from https://developer.android.com/ndk/downloads/index.html
ENV ANDROID_NDK_ARCHIVE="android-ndk-r${ANDROID_NDK_VERSION}-linux.zip"
ENV ANDROID_NDK_DL_URL="https://dl.google.com/android/repository/${ANDROID_NDK_ARCHIVE}"

# download and install Android NDK
RUN curl --location --progress-bar \
        "${ANDROID_NDK_DL_URL}" \
        --output "${ANDROID_NDK_ARCHIVE}" \
    && echo "${ANDROID_NDK_HASH} ${ANDROID_NDK_ARCHIVE}" | sha256sum -c - \
    && mkdir --parents "${ANDROID_NDK_HOME_V}" \
    && unzip -q "${ANDROID_NDK_ARCHIVE}" -d "${ANDROID_HOME}" \
    && ln -sfn "${ANDROID_NDK_HOME_V}" "${ANDROID_NDK_HOME}" \
    && rm -rf "${ANDROID_NDK_ARCHIVE}"


ENV ANDROID_SDK_HOME="${ANDROID_HOME}/android-sdk"

# get the latest version from https://developer.android.com/studio/index.html
ENV ANDROID_SDK_TOOLS_VERSION="9477386"
ENV ANDROID_SDK_HASH="bd1aa17c7ef10066949c88dc6c9c8d536be27f992a1f3b5a584f9bd2ba5646a0"
ENV ANDROID_SDK_TOOLS_ARCHIVE="commandlinetools-linux-${ANDROID_SDK_TOOLS_VERSION}_latest.zip"
ENV ANDROID_SDK_TOOLS_DL_URL="https://dl.google.com/android/repository/${ANDROID_SDK_TOOLS_ARCHIVE}"
ENV ANDROID_SDK_MANAGER="${ANDROID_SDK_HOME}/cmdline-tools/bin/sdkmanager --sdk_root=${ANDROID_SDK_HOME}"

# download and install Android SDK
RUN curl --location --progress-bar \
        "${ANDROID_SDK_TOOLS_DL_URL}" \
        --output "${ANDROID_SDK_TOOLS_ARCHIVE}" \
    && echo "${ANDROID_SDK_HASH} ${ANDROID_SDK_TOOLS_ARCHIVE}" | sha256sum -c - \
    && mkdir --parents "${ANDROID_SDK_HOME}" \
    && unzip -q "${ANDROID_SDK_TOOLS_ARCHIVE}" -d "${ANDROID_SDK_HOME}" \
    && rm -rf "${ANDROID_SDK_TOOLS_ARCHIVE}"

# update Android SDK, install Android API, Build Tools...
RUN mkdir --parents "${ANDROID_SDK_HOME}/.android/" \
    && echo '### User Sources for Android SDK Manager' \
        > "${ANDROID_SDK_HOME}/.android/repositories.cfg"

# accept Android licenses (JDK necessary!)
RUN apt -y update -qq \
    && apt -y install -qq --no-install-recommends --allow-downgrades \
        openjdk-17-jdk-headless \
    && apt -y autoremove
RUN yes | ${ANDROID_SDK_MANAGER} --licenses > /dev/null


ENV ANDROID_SDK_BUILD_TOOLS_VERSION="31.0.0"

# download platforms, API, build tools
RUN ${ANDROID_SDK_MANAGER} "platforms;android-31" > /dev/null && \
    ${ANDROID_SDK_MANAGER} "build-tools;${ANDROID_SDK_BUILD_TOOLS_VERSION}" > /dev/null && \
    ${ANDROID_SDK_MANAGER} "extras;android;m2repository" > /dev/null && \
    chmod +x "${ANDROID_SDK_HOME}/cmdline-tools/bin/avdmanager"

# download ANT
ENV APACHE_ANT_VERSION="1.10.13"
ENV APACHE_ANT_HASH="776be4a5704158f00ef3f23c0327546e38159389bc8f39abbfe114913f88bab1"
ENV APACHE_ANT_ARCHIVE="apache-ant-${APACHE_ANT_VERSION}-bin.tar.gz"
ENV APACHE_ANT_DL_URL="https://archive.apache.org/dist/ant/binaries/${APACHE_ANT_ARCHIVE}"
ENV APACHE_ANT_HOME="${ANDROID_HOME}/apache-ant"
ENV APACHE_ANT_HOME_V="${APACHE_ANT_HOME}-${APACHE_ANT_VERSION}"

RUN curl --location --progress-bar \
        "${APACHE_ANT_DL_URL}" \
        --output "${APACHE_ANT_ARCHIVE}" \
    && echo "${APACHE_ANT_HASH} ${APACHE_ANT_ARCHIVE}" | sha256sum -c - \
    && tar -xf "${APACHE_ANT_ARCHIVE}" -C "${ANDROID_HOME}" \
    && ln -sfn "${APACHE_ANT_HOME_V}" "${APACHE_ANT_HOME}" \
    && rm -rf "${APACHE_ANT_ARCHIVE}"


# install system/build dependencies
# https://github.com/kivy/buildozer/blob/master/docs/source/installation.rst#android-on-ubuntu-2004-64bit
RUN apt -y update -q \
    && apt -y install -q --no-install-recommends --allow-downgrades \
        python3 \
        python3-dev \
        python3-pip \
        python3-setuptools \
        python3-venv \
        wget \
        lbzip2 \
        patch \
        sudo \
        software-properties-common \
        git \
        zip \
        unzip \
        rsync \
        build-essential \
        ccache \
        autoconf \
        autopoint \
        libtool \
        pkg-config \
        zlib1g-dev \
        libncurses5-dev \
        libncursesw5-dev \
        libtinfo5 \
        cmake \
        libffi-dev \
        libssl-dev \
        automake \
        gettext \
        libltdl-dev \
    && apt -y autoremove \
    && apt -y clean

# cross compile deps for Qt6
RUN apt -y update -qq \
    && apt -y install -qq --no-install-recommends --allow-downgrades \
        libopengl-dev \
        libegl-dev \
        dos2unix \
    && apt -y autoremove \
    && apt -y clean


# create new user to avoid using root; but with sudo access and no password for convenience.
ARG UID=1000
ENV USER="user"
ENV HOME_DIR="/home/${USER}"
ENV WORK_DIR="${HOME_DIR}/wspace" \
    PATH="${HOME_DIR}/.local/bin:${PATH}"
RUN useradd --uid $UID --create-home --shell /bin/bash ${USER}
RUN usermod -append --groups sudo ${USER}
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
WORKDIR ${WORK_DIR}
RUN chown --recursive ${USER} ${WORK_DIR} ${ANDROID_SDK_HOME}
RUN chown ${USER} /opt
USER ${USER}

# venv, VIRTUAL_ENV is used by buildozer to indicate a venv environment
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv ${VIRTUAL_ENV}
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

COPY contrib/deterministic-build/requirements-build-base.txt /opt/deterministic-build/
COPY contrib/deterministic-build/requirements-build-android.txt /opt/deterministic-build/
RUN /opt/venv/bin/python3 -m pip install --no-build-isolation --no-dependencies \
    -r /opt/deterministic-build/requirements-build-base.txt
RUN /opt/venv/bin/python3 -m pip install --no-build-isolation --no-dependencies --no-binary :all: \
    -r /opt/deterministic-build/requirements-build-android.txt

# install buildozer
RUN cd /opt \
    && git clone https://github.com/kivy/buildozer \
    && cd buildozer \
    && git remote add sombernight https://github.com/SomberNight/buildozer \
    && git remote add accumulator https://github.com/accumulator/buildozer \
    && git fetch --all \
    # commit: from branch electrum-qt6 (note: careful with force-pushing! see #8162) \
    && git checkout "4403ecf445f10b5fbf7c74f4621bf2b922ad35b5^{commit}" \
    && /opt/venv/bin/python3 -m pip install --no-build-isolation --no-dependencies -e .

# install python-for-android
RUN cd /opt \
    && git clone https://github.com/kivy/python-for-android \
    && cd python-for-android \
    && git remote add sombernight https://github.com/SomberNight/python-for-android \
    && git remote add accumulator https://github.com/accumulator/python-for-android \
    && git fetch --all \
    # commit: from branch sombernight/qt6-wip (note: careful with force-pushing! see #8162) \
    && git checkout "5df11be775eadcc19774e5bb118ee407330b8d83^{commit}" \
    && /opt/venv/bin/python3 -m pip install --no-build-isolation --no-dependencies -e .

# build env vars
ENV USE_SDK_WRAPPER=1
ENV GRADLE_OPTS="-Xmx1536M -Dorg.gradle.jvmargs='-Xmx1536M'"
#ENV P4A_FULL_DEBUG=1
