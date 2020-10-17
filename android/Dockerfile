# This image must be built in the context of the repository root.

FROM debian:stretch-20180831
SHELL ["/bin/bash", "-c"]
WORKDIR /root

RUN apt-get update && \
    apt-get install -y gettext openjdk-8-jdk-headless unzip wget
RUN echo "progress=dot:giga" > .wgetrc

RUN filename=sdk-tools-linux-4333796.zip && \
    wget https://dl.google.com/android/repository/$filename && \
    mkdir android-sdk && \
    unzip -q -d android-sdk $filename && \
    rm $filename

# Indicate that we accept the Android SDK license. The platform version here isn't critical:
# all versions require the same license, and if app/build.gradle specifies a different version,
# the build process will automatically download it.
RUN yes | android-sdk/tools/bin/sdkmanager "platforms;android-28"

# Python 3.6 isn't included in this version of Debian, so use a third-party build.
RUN apt-get update && \
    wget https://github.com/chriskuehl/python3.6-debian-stretch/releases/download/v3.6.3-1-deb9u1/{python3.6,python3.6-minimal,libpython3.6,libpython3.6-minimal,libpython3.6-stdlib}_3.6.3-1.deb9u1_amd64.deb && \
    apt install -y ./*.deb && \
    rm *.deb && \
    ln -s python3.6 /usr/bin/python3

# For generate_strings.py.
COPY android/build-requirements.txt android/
RUN wget -O - https://bootstrap.pypa.io/get-pip.py | python3.6 && \
    pip3 install -r android/build-requirements.txt
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
