# based on https://github.com/kivy/python-for-android/blob/master/Dockerfile

FROM debian:trixie@sha256:a3b5f4f0286249a124bfe9845b3aec0f88de32ff31dd8d7e1b945f9f98d116b0

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
    ca-certificates \
    python3 \
    && apt -y autoremove


ENV ANDROID_NDK_HOME="${ANDROID_HOME}/android-ndk"
#ENV ANDROID_NDK_VERSION="23b"
#ENV ANDROID_NDK_HASH="c6e97f9c8cfe5b7be0a9e6c15af8e7a179475b7ded23e2d1c1fa0945d6fb4382"
#ENV ANDROID_NDK_VERSION="27d"
#ENV ANDROID_NDK_HASH="601246087a682d1944e1e16dd85bc6e49560fe8b6d61255be2829178c8ed15d9"
ENV ANDROID_NDK_VERSION="23d-canary"
ENV ANDROID_NDK_HASH="6944ffc20ab018ff4ef6a403048d0a99d50a0630c3eae690c8f803c452f46f3e"
ENV ANDROID_NDK_HOME_V="${ANDROID_NDK_HOME}-r${ANDROID_NDK_VERSION}"

# get the latest version from https://developer.android.com/ndk/downloads/index.html
ENV ANDROID_NDK_ARCHIVE="android-ndk-r${ANDROID_NDK_VERSION}-linux.zip"
ENV ANDROID_NDK_DL_URL="https://dl.google.com/android/repository/${ANDROID_NDK_ARCHIVE}"

# below disabled in favor of CI build download

# download and install Android NDK
#RUN curl --location --progress-bar \
#        "${ANDROID_NDK_DL_URL}" \
#        --output "${ANDROID_NDK_ARCHIVE}" \
#    && echo "${ANDROID_NDK_HASH} ${ANDROID_NDK_ARCHIVE}" | sha256sum -c - \
#    && mkdir --parents "${ANDROID_NDK_HOME_V}" \
#    && unzip -q "${ANDROID_NDK_ARCHIVE}" -d "${ANDROID_HOME}" \
#    && ln -sfn "${ANDROID_NDK_HOME_V}" "${ANDROID_NDK_HOME}" \
#    && rm -rf "${ANDROID_NDK_ARCHIVE}"

# temporary build using NDK from CI
ENV CI_REV="12186248"
ENV CI_NDK_FILE="android-ndk-${CI_REV}-linux-x86_64.zip"
COPY contrib/android/dl-ndk-ci.sh /tmp/
RUN /tmp/dl-ndk-ci.sh https://ci.android.com/builds/submitted/${CI_REV}/linux/latest/${CI_NDK_FILE} \
    && echo "${ANDROID_NDK_HASH} android-ndk-ci-linux-x86_64.zip" | sha256sum -c - \
    && mkdir --parents "${ANDROID_NDK_HOME_V}" \
    && unzip -q "android-ndk-ci-linux-x86_64.zip" -d "${ANDROID_HOME}" \
    && ln -sfn "${ANDROID_NDK_HOME_V}" "${ANDROID_NDK_HOME}" \
    && rm -rf "android-ndk-ci-linux-x86_64.zip"

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

# download Java-17 (debian 13 only packages Java-21 and Java-25)
# - we download the amd64 binaries from debian 12 repos
# - we should try to upgrade to Java-21...
#   - the main blocker seems to be having to update Gradle (to a version compatible with Java-21)
#     - make_barcode_scanner.sh: markusfisch/{zxing-cpp, ...} pins old Gradle
ENV JAVA_JRE_DL_URL="https://snapshot.debian.org/archive/debian/20260130T143028Z/pool/main/o/openjdk-17/openjdk-17-jre-headless_17.0.18+8-1~deb12u1_amd64.deb"
ENV JAVA_JRE_ARCHIVE="openjdk-17-jre-headless.deb"
ENV JAVA_JRE_HASH="5bc36cbb4e383dbea4168d57b5fd9b42375ec8837dd62a1d56677632c3c960e0"
ENV JAVA_JDK_DL_URL="https://snapshot.debian.org/archive/debian/20260130T143028Z/pool/main/o/openjdk-17/openjdk-17-jdk-headless_17.0.18+8-1~deb12u1_amd64.deb"
ENV JAVA_JDK_ARCHIVE="openjdk-17-jdk-headless.deb"
ENV JAVA_JDK_HASH="8841044caa66860a71039342fe3c02b7853b61c518e05970e501faa215b1788a"
RUN apt -y update -qq \
    && apt -y install -qq --no-install-recommends \
        ca-certificates-java \
        java-common \
        libcups2 \
        libfontconfig1 \
        liblcms2-2 \
        libjpeg62-turbo \
        libnss3 \
        libasound2 \
        libfreetype6 \
        libharfbuzz0b \
        libpcsclite1 \
    && apt -y autoremove \
    && cd /opt \
    && curl --location --progress-bar "${JAVA_JRE_DL_URL}" --output "${JAVA_JRE_ARCHIVE}" \
    && echo "${JAVA_JRE_HASH} ${JAVA_JRE_ARCHIVE}" | sha256sum -c - \
    && dpkg -i "${JAVA_JRE_ARCHIVE}" \
    && rm "${JAVA_JRE_ARCHIVE}" \
    && curl --location --progress-bar "${JAVA_JDK_DL_URL}" --output "${JAVA_JDK_ARCHIVE}" \
    && echo "${JAVA_JDK_HASH} ${JAVA_JDK_ARCHIVE}" | sha256sum -c - \
    && dpkg -i "${JAVA_JDK_ARCHIVE}" \
    && rm "${JAVA_JDK_ARCHIVE}"

# accept Android licenses (JDK necessary!)
RUN yes | ${ANDROID_SDK_MANAGER} --licenses > /dev/null


ENV ANDROID_SDK_BUILD_TOOLS_MAJOR_V="31"
ENV ANDROID_SDK_BUILD_TOOLS_VERSION="31.0.0"

# download platforms, API, build tools
RUN ${ANDROID_SDK_MANAGER} "platforms;android-${ANDROID_SDK_BUILD_TOOLS_MAJOR_V}" > /dev/null && \
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
        dos2unix \
    && apt -y autoremove \
    && apt -y clean


# create new user to avoid using root; but with sudo access and no password for convenience.
ARG UID=1000
RUN if [ "$UID" != "0" ] ; then useradd --uid $UID --create-home --shell /bin/bash "user" ; fi
RUN usermod -append --groups sudo $(id -nu $UID || echo "user")
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
RUN HOME_DIR=$(getent passwd $UID | cut -d: -f6)
ENV WORK_DIR="${HOME_DIR}/wspace" \
    PATH="${HOME_DIR}/.local/bin:${PATH}"
WORKDIR ${WORK_DIR}
RUN chown --recursive ${UID} ${WORK_DIR} ${ANDROID_SDK_HOME}
RUN chown ${UID} /opt
USER ${UID}

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

COPY contrib/deterministic-build/requirements-build-base.txt /opt/deterministic-build/
COPY contrib/deterministic-build/requirements-build-android.txt /opt/deterministic-build/
RUN /opt/venv/bin/python3 -m pip install --no-build-isolation --no-dependencies \
    -r /opt/deterministic-build/requirements-build-base.txt
RUN /opt/venv/bin/python3 -m pip install --no-build-isolation --no-dependencies --no-binary :all: \
    -r /opt/deterministic-build/requirements-build-android.txt

# install buildozer
ENV BUILDOZER_CHECKOUT_COMMIT="4403ecf445f10b5fbf7c74f4621bf2b922ad35b5"
# ^ from branch electrum_20240930 (note: careful with force-pushing! see #8162)
RUN cd /opt \
    && git clone https://github.com/spesmilo/buildozer \
    && cd buildozer \
    && git checkout "${BUILDOZER_CHECKOUT_COMMIT}^{commit}" \
    && /opt/venv/bin/python3 -m pip install --no-build-isolation --no-dependencies -e .

# install python-for-android
ENV P4A_CHECKOUT_COMMIT="a01269f7799587ad74ee40e0b642d917b8db7d4e"
# ^ from branch electrum_20251211 (note: careful with force-pushing! see #8162)
RUN cd /opt \
    && git clone https://github.com/spesmilo/python-for-android \
    && cd python-for-android \
    && git checkout "${P4A_CHECKOUT_COMMIT}^{commit}" \
    && /opt/venv/bin/python3 -m pip install --no-build-isolation --no-dependencies -e .

# build env vars
ENV USE_SDK_WRAPPER=1
ENV GRADLE_OPTS="-Xmx1536M -Dorg.gradle.jvmargs='-Xmx1536M'"
#ENV P4A_FULL_DEBUG=1
