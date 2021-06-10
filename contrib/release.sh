#
# Note: update locale before:
# 1. cd /opt/electrum-locale && ./update && push
# 2. cd to the submodule dir, and git pull
# 3. cd .. && git push
#!/bin/bash

ELECTRUM_DIR=/opt/electrum
WWW_DIR=/opt/electrum-web


cd $ELECTRUM_DIR
# rm -rf dist/*
# rm -f .buildozer


VERSION=`python3 -c "import electrum; print(electrum.version.ELECTRUM_VERSION)"`
echo "VERSION: $VERSION"
REV=`git describe --tags`
echo "REV: $REV"
COMMIT=$(git rev-parse HEAD)


git_status=$(git status --porcelain)
if [ ! -z "$git_status" ]; then
    echo "$git_status"
    echo "git repo not clean, aborting"
    exit 1
fi

set -ex

# create tarball
target=Electrum-$VERSION.tar.gz
if test -f dist/$target; then
    echo "file exists: $target"
else
   pushd .
   sudo docker build -t electrum-sdist-builder-img contrib/build-linux/sdist
   FRESH_CLONE=contrib/build-linux/sdist/fresh_clone && \
       sudo rm -rf $FRESH_CLONE && \
       umask 0022 && \
       mkdir -p $FRESH_CLONE && \
       cd $FRESH_CLONE  && \
       git clone https://github.com/spesmilo/electrum.git &&\
       cd electrum
   git checkout "${COMMIT}^{commit}"
   sudo docker run -it \
	--name electrum-sdist-builder-cont \
	-v $PWD:/opt/electrum \
	--rm \
	--workdir /opt/electrum/contrib/build-linux/sdist \
	electrum-sdist-builder-img \
	./build.sh
   popd
   cp /opt/electrum/contrib/build-linux/sdist/fresh_clone/electrum/dist/$target dist/
fi

# appimage
if [ $REV != $VERSION ]; then
    target=electrum-${REV:0:-2}-x86_64.AppImage
else
    target=electrum-$REV-x86_64.AppImage
fi

if test -f dist/$target; then
    echo "file exists: $target"
else
    sudo docker build -t electrum-appimage-builder-img contrib/build-linux/appimage
    sudo docker run -it \
         --name electrum-appimage-builder-cont \
	 -v $PWD:/opt/electrum \
         --rm \
	 --workdir /opt/electrum/contrib/build-linux/appimage \
         electrum-appimage-builder-img \
	 ./build.sh
fi


# windows
target=electrum-$REV.exe
if test -f dist/$target; then
    echo "file exists: $target"
else
    pushd .
    FRESH_CLONE=contrib/build-wine/fresh_clone && \
        sudo rm -rf $FRESH_CLONE && \
        mkdir -p $FRESH_CLONE && \
        cd $FRESH_CLONE  && \
        git clone https://github.com/spesmilo/electrum.git && \
        cd electrum
    git checkout "${COMMIT}^{commit}"
    sudo docker run -it \
        --name electrum-wine-builder-cont \
        -v $PWD:/opt/wine64/drive_c/electrum \
        --rm \
        --workdir /opt/wine64/drive_c/electrum/contrib/build-wine \
        electrum-wine-builder-img \
        ./build.sh
    # do this in the fresh clone directorry!
    cd contrib/build-wine/
    ./sign.sh
    cp ./signed/*.exe /opt/electrum/dist/
    popd
fi

# android
target1=Electrum-$VERSION.0-armeabi-v7a-release.apk
target2=Electrum-$VERSION.0-arm64-v8a-release.apk

if test -f dist/$target1; then
    echo "file exists: $target1"
else
    ./contrib/android/build_docker_image.sh
    FRESH_CLONE=contrib/android/fresh_clone && \
        sudo rm -rf $FRESH_CLONE && \
        umask 0022 && \
        mkdir -p $FRESH_CLONE && \
        cd $FRESH_CLONE  && \
        git clone https://github.com/spesmilo/electrum.git && \
        cd electrum

    mkdir --parents $PWD/.buildozer/.gradle
    sudo docker run -it --rm \
         --name electrum-android-builder-cont \
         -v $PWD:/home/user/wspace/electrum \
         -v $PWD/.buildozer/.gradle:/home/user/.gradle \
         -v ~/.keystore:/home/user/.keystore \
         --workdir /home/user/wspace/electrum \
         electrum-android-builder-img \
         ./contrib/android/make_apk release

    cp bin/$target1 dist/
    cp bin/$target2 dist/

fi


# wait for dmg before signing
if test -f dist/electrum-$VERSION.dmg; then
    if test -f dist/electrum-$VERSION.dmg.asc; then
	echo "packages are already signed"
    else
	echo "signing packages"
	./contrib/sign_packages ThomasV
    fi
else
    echo "dmg is missing, aborting"
    exit 1
fi

echo "build complete"
sha256sum dist/*.tar.gz
sha256sum dist/*.AppImage
sha256sum contrib/build-wine/fresh_clone/electrum/contrib/build-wine/dist/*.exe

echo -n "proceed (y/n)? "
read answer

if [ "$answer" != "y" ] ;then
    echo "exit"
    exit 1
fi


echo "updating www repo"
./contrib/make_download $WWW_DIR
echo "signing the version file"
sig=`./run_electrum -o signmessage $ELECTRUM_SIGNING_ADDRESS $VERSION -w $ELECTRUM_SIGNING_WALLET`
echo "{ \"version\":\"$VERSION\", \"signatures\":{ \"$ELECTRUM_SIGNING_ADDRESS\":\"$sig\"}}" > $WWW_DIR/version


if [ $REV != $VERSION ]; then
    echo "versions differ, not uploading"
    exit 1
fi

# upload the files
if test -f dist/uploaded; then
    echo "files already uploaded"
else
    ./contrib/upload
    touch dist/uploaded
fi


# push changes to website repo
pushd $WWW_DIR
git diff
git commit -a -m "version $VERSION"
git push
popd

echo "run $WWW_DIR/publish.sh to sign the website commit and upload signature"
