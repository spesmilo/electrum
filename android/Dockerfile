# This image must be built in the context of the repository root.

# The Android Gradle plugin still requires Java 8, so use a Debian version which includes that.
FROM debian:stretch-20180831
SHELL ["/bin/bash", "-c"]
WORKDIR /root

RUN apt-get update && \
    apt-get install -y openjdk-8-jdk-headless unzip wget
RUN echo "progress=dot:giga" > .wgetrc

# Install the same minor Python version as Chaquopy uses.
RUN apt-get update && \
    apt-get install -y gcc libbz2-dev libffi-dev liblzma-dev libsqlite3-dev libssl-dev \
                       zlib1g-dev make
RUN version=3.8.7 && \
    wget https://www.python.org/ftp/python/$version/Python-$version.tgz && \
    tar -xf Python-$version.tgz && \
    cd Python-$version && \
    ./configure && \
    make -j $(nproc) && \
    make install && \
    cd .. && \
    rm -r Python-$version*

RUN filename=commandlinetools-linux-6609375_latest.zip && \
    wget https://dl.google.com/android/repository/$filename && \
    mkdir -p android-sdk/cmdline-tools && \
    unzip -q -d android-sdk/cmdline-tools $filename && \
    rm $filename

# Indicate that we accept the Android SDK license. The platform version here isn't critical:
# all versions require the same license, and if app/build.gradle has a different
# compileSdkVersion, the build process will automatically download it.
RUN yes | android-sdk/cmdline-tools/tools/bin/sdkmanager "platforms;android-29"

# For generate_strings.py.
RUN apt-get update && \
    apt-get install -y gettext
COPY android/build-requirements.txt android/
RUN pip3 install -r android/build-requirements.txt
COPY contrib/make_locale contrib/
COPY electroncash_gui electroncash_gui
COPY ios/ElectronCash/electroncash_gui/ios_native ios/ElectronCash/electroncash_gui/ios_native
COPY electroncash_plugins electroncash_plugins

# The app itself. Specifically check for the keystore, otherwise it'll build an APK with no
# certificates.
COPY android android
COPY android/keystore.jks android/
COPY contrib/deterministic-build contrib/deterministic-build
COPY electroncash electroncash

RUN echo "sdk.dir=$(pwd)/android-sdk" > android/local.properties
RUN cd android && ./gradlew app:assembleMainNetRelease
