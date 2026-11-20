# based on https://github.com/kivy/python-for-android/blob/master/Dockerfile

FROM debian:trixie@sha256:bfc36aecdece0387418759dba474aa856c026ca8087da3606b41b90ab0509c99

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
    wget \
    unzip \
    python3 \
    && apt -y autoremove


ENV ANDROID_NDK_HOME="${ANDROID_HOME}/android-ndk"
ENV ANDROID_NDK_VERSION="28c"
ENV ANDROID_NDK_HASH="dfb20d396df28ca02a8c708314b814a4d961dc9074f9a161932746f815aa552f"
ENV ANDROID_NDK_HOME_V="${ANDROID_NDK_HOME}-r${ANDROID_NDK_VERSION}"

# get the latest version from https://developer.android.com/ndk/downloads/index.html
ENV ANDROID_NDK_ARCHIVE="android-ndk-r${ANDROID_NDK_VERSION}-linux.zip"
ENV ANDROID_NDK_DL_URL="https://dl.google.com/android/repository/${ANDROID_NDK_ARCHIVE}"

# below disabled in favor of CI build download

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
ENV ANDROID_SDK_TOOLS_VERSION="14742923"
ENV ANDROID_SDK_HASH="04453066b540409d975c676d781da1477479dde3761310f1a7eb92a1dfb15af7"

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

# install Java
RUN apt -y update -qq \
    && apt -y install -qq --no-install-recommends --allow-downgrades \
        openjdk-21-jdk-headless \
    && apt -y autoremove

ENV ANDROID_SDK_BUILD_TOOLS_MAJOR_V="36"
ENV ANDROID_SDK_BUILD_TOOLS_VERSION="36.0.0"

# the archive names of the SDK packages are listed in https://dl.google.com/android/repository/repository2-3.xml
ENV ANDROID_SDK_PACKAGES_DL_URL="https://dl.google.com/android/repository"
ENV ANDROID_SDK_PLATFORM_ARCHIVE="platform-36_r02.zip"
ENV ANDROID_SDK_PLATFORM_HASH="37607369a28c5b640b3a7998868d45898ebcb777565a0e85f9acf36f29631d2e"
ENV ANDROID_SDK_BUILD_TOOLS_ARCHIVE="build-tools_r36_linux.zip"
ENV ANDROID_SDK_BUILD_TOOLS_HASH="5d9ac77fb6ff43d9da518a337b4fcf8f9097113df531d99ccefe80ef7ce8250b"

# download and install the Android platform (API) and build tools (not through sdkmanager so we can hash pin them)
RUN curl --location --progress-bar \
        "${ANDROID_SDK_PACKAGES_DL_URL}/${ANDROID_SDK_PLATFORM_ARCHIVE}" \
        --output "${ANDROID_SDK_PLATFORM_ARCHIVE}" \
    && echo "${ANDROID_SDK_PLATFORM_HASH} ${ANDROID_SDK_PLATFORM_ARCHIVE}" | sha256sum -c - \
    && unzip -q "${ANDROID_SDK_PLATFORM_ARCHIVE}" -d platform-unpacked \
    && mkdir --parents "${ANDROID_SDK_HOME}/platforms" \
    && mv platform-unpacked/* "${ANDROID_SDK_HOME}/platforms/android-${ANDROID_SDK_BUILD_TOOLS_MAJOR_V}" \
    && rmdir platform-unpacked \
    && rm -rf "${ANDROID_SDK_PLATFORM_ARCHIVE}"

RUN curl --location --progress-bar \
        "${ANDROID_SDK_PACKAGES_DL_URL}/${ANDROID_SDK_BUILD_TOOLS_ARCHIVE}" \
        --output "${ANDROID_SDK_BUILD_TOOLS_ARCHIVE}" \
    && echo "${ANDROID_SDK_BUILD_TOOLS_HASH} ${ANDROID_SDK_BUILD_TOOLS_ARCHIVE}" | sha256sum -c - \
    && unzip -q "${ANDROID_SDK_BUILD_TOOLS_ARCHIVE}" -d build-tools-unpacked \
    && mkdir --parents "${ANDROID_SDK_HOME}/build-tools" \
    && mv build-tools-unpacked/* "${ANDROID_SDK_HOME}/build-tools/${ANDROID_SDK_BUILD_TOOLS_VERSION}" \
    && rmdir build-tools-unpacked \
    && rm -rf "${ANDROID_SDK_BUILD_TOOLS_ARCHIVE}"

# let sdkmanager write the package.xml of the two packages, this does not use the network (JDK necessary!).
# Without it, avdmanager does not list the platform, and python-for-android asks avdmanager for the available APIs.
RUN ${ANDROID_SDK_MANAGER} --list_installed > /dev/null


# install system/build dependencies
# https://github.com/kivy/buildozer/blob/master/docs/source/installation.rst#android-on-ubuntu-2004-64bit
RUN apt -y update -q \
    && apt -y install -q --no-install-recommends --allow-downgrades \
        wget \
        lbzip2 \
        patch \
        sudo \
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
        libncurses-dev \
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
        ninja-build \
    && apt -y autoremove \
    && apt -y clean


# create new user to avoid using root; but with sudo access and no password for convenience.
ARG UID=1000
RUN useradd -u "$UID" -m -s /usr/bin/bash -d /home/user user
RUN usermod -aG sudo user
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
ENV HOME_DIR=/home/user
ENV WORK_DIR="${HOME_DIR}/wspace"
ENV PATH="${HOME_DIR}/.local/bin:${PATH}"
WORKDIR ${WORK_DIR}
RUN chown -R user ${WORK_DIR} ${ANDROID_SDK_HOME} /opt
USER user

# build cpython. FIXME we can't use the python3 from apt, as it is too new o.O
# - p4a and buildozer require cython<3 (see https://github.com/kivy/python-for-android/issues/2919)
#   but the last such version, cython 0.29.37, can only be built by up to python 3.12
ENV VENV_PYTHON_VERSION="3.12.12"
ENV VENV_PY_VER_MAJOR="3.12"
ENV VENV_PYTHON_HASH="487c908ddf4097a1b9ba859f25fe46d22ccaabfb335880faac305ac62bffb79b"
RUN mkdir --parents "/opt/cpython/download" && cd "/opt/cpython/download" \
    && wget "https://www.python.org/ftp/python/${VENV_PYTHON_VERSION}/Python-${VENV_PYTHON_VERSION}.tgz" \
    && echo "${VENV_PYTHON_HASH} Python-${VENV_PYTHON_VERSION}.tgz" | sha256sum -c - \
    && tar xf "Python-${VENV_PYTHON_VERSION}.tgz" -C "/opt/cpython/download" \
    && cd "Python-${VENV_PYTHON_VERSION}" \
    && mkdir "/opt/cpython/install" \
    && ./configure \
        --prefix="/opt/cpython/install" \
        -q \
    && make "-j$(nproc)" -s \
    && make -s altinstall \
    && ln -s "/opt/cpython/install/bin/python${VENV_PY_VER_MAJOR}" "/opt/cpython/install/bin/python3"
RUN "/opt/cpython/install/bin/python3" -m ensurepip

# venv, VIRTUAL_ENV is used by buildozer to indicate a venv environment
ENV VIRTUAL_ENV=/opt/venv
RUN "/opt/cpython/install/bin/python3" -m venv ${VIRTUAL_ENV}
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

COPY --chown=user contrib/deterministic-build/requirements-build-base.txt /opt/deterministic-build/
COPY --chown=user contrib/deterministic-build/requirements-build-android.txt /opt/deterministic-build/
RUN /opt/venv/bin/python3 -m pip install --no-build-isolation --no-dependencies \
    -r /opt/deterministic-build/requirements-build-base.txt
RUN /opt/venv/bin/python3 -m pip install --no-build-isolation --no-dependencies --no-binary :all: \
    -r /opt/deterministic-build/requirements-build-android.txt

# install buildozer
ENV BUILDOZER_CHECKOUT_COMMIT="6c4a4de72782d218834b5d250d30814d56d8e8da"
# ^ from branch electrum_20261120 (note: careful with force-pushing! see #8162)
RUN cd /opt \
    && git clone https://github.com/spesmilo/buildozer \
    && cd buildozer \
    && git checkout "${BUILDOZER_CHECKOUT_COMMIT}^{commit}" \
    && /opt/venv/bin/python3 -m pip install --no-build-isolation --no-dependencies -e .

# install python-for-android
ENV P4A_CHECKOUT_COMMIT="7347c85b570c2af093d31270db338fa3a3dcbb06"
# ^ from branch Aelectrum_202612 (note: careful with force-pushing! see #8162)
RUN cd /opt \
    && git clone https://github.com/spesmilo/python-for-android \
    && cd python-for-android \
    && git checkout "${P4A_CHECKOUT_COMMIT}^{commit}" \
    && /opt/venv/bin/python3 -m pip install --no-build-isolation --no-dependencies -e .

# pin the sha256 of everything gradle downloads for the apk build.
# python-for-android copies this file into the gradle project, along with the rest of the bootstrap dir.
# To update it, run contrib/android/update_gradle_verification_metadata.sh
COPY --chown=user contrib/android/gradle-verification-metadata.xml \
    /opt/python-for-android/pythonforandroid/bootstraps/qt6/build/gradle/verification-metadata.xml

# build env vars
ENV USE_SDK_WRAPPER=1
ENV GRADLE_OPTS="-Xmx1536M -Dorg.gradle.jvmargs='-Xmx1536M'"
#ENV P4A_FULL_DEBUG=1
