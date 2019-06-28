AppImage binary for Electrum-LTC
================================

✓ _This binary should be reproducible, meaning you should be able to generate
   binaries that match the official releases._

This assumes an Ubuntu host, but it should not be too hard to adapt to another
similar system. The host architecture should be x86_64 (amd64).
The docker commands should be executed in the project's root folder.

We currently only build a single AppImage, for x86_64 architecture.
Help to adapt these scripts to build for (some flavor of) ARM would be welcome,
see [issue #5159](https://github.com/spesmilo/electrum/issues/5159).


1. Install Docker

    ```
    $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    $ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    $ sudo apt-get update
    $ sudo apt-get install -y docker-ce
    ```

2. Build image

    ```
    $ sudo docker build --no-cache -t electrum-ltc-appimage-builder-img contrib/build-linux/appimage
    ```

3. Build binary

    ```
    $ sudo docker run -it \
        --name electrum-ltc-appimage-builder-cont \
        -v $PWD:/opt/electrum-ltc \
        --rm \
        --workdir /opt/electrum-ltc/contrib/build-linux/appimage \
        electrum-ltc-appimage-builder-img \
        ./build.sh
    ```

4. The generated binary is in `./dist`.


## FAQ

### How can I see what is included in the AppImage?
Execute the binary as follows: `./electrum*.AppImage --appimage-extract`
