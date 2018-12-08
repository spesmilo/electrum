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

# Indicate that we accept the license which has the given hash.
RUN mkdir android-sdk/licenses && \
    echo d56f5187479451eabf01fb78af6dfcb131a6481e > android-sdk/licenses/android-sdk-license

# make_locale
RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    pip3 install requests
COPY contrib/make_locale contrib/
COPY gui gui
COPY ios/ElectronCash/electroncash_gui/ios_native ios/ElectronCash/electroncash_gui/ios_native
COPY plugins plugins

# The app itself
COPY android android
COPY contrib/deterministic-build contrib/deterministic-build
COPY lib lib

RUN echo "sdk.dir=$(pwd)/android-sdk" > android/local.properties
RUN cd android && ./gradlew app:assembleRelease
