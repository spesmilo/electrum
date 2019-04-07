AppImage binary for Electron Cash
============================

This assumes an Ubuntu host, but it should not be too hard to adapt to another
similar system. The docker commands should be executed in the project's root
folder.

1. Install Docker

    ```
    $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    $ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    $ sudo apt-get update
    $ sudo apt-get install -y docker-ce
    ```

2. Build image

    ```
    $ sudo docker build --no-cache -t electroncash-appimage-builder-img contrib/build-linux/appimage
    ```

    _Note:_ If you are using a MacOS host, run the above **without** `sudo`.

3. Build binary

    ```
    $ sudo docker run -it \
        --name electroncash-appimage-builder-cont \
        -v $PWD:/opt/electroncash \
        --rm \
        --workdir /opt/electroncash/contrib/build-linux/appimage \
        electroncash-appimage-builder-img \
        ./_build.sh REVISION_TAG_OR_BRANCH_OR_COMMIT_TAG
    ```

    _Note:_ If you are using a MacOS host, run the above **without** `sudo`.

4. The generated .AppImage binary is in `./dist`.


## FAQ

### How can I see what is included in the AppImage?
Execute the binary as follows: `./Electron-Cash*.AppImage --appimage-extract`
