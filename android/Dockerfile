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

# For generate_strings.py.
RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    pip3 install polib requests
COPY contrib/make_locale contrib/
COPY gui gui
COPY ios/ElectronCash/electroncash_gui/ios_native ios/ElectronCash/electroncash_gui/ios_native
COPY plugins plugins

# The app itself. Specifically check for the keystore, otherwise it'll build an APK with no
# certificates.
COPY android android
COPY android/keystore.jks android/
COPY contrib/deterministic-build contrib/deterministic-build
COPY lib lib

RUN echo "sdk.dir=$(pwd)/android-sdk" > android/local.properties
RUN cd android && ./gradlew app:assembleMainNetRelease
