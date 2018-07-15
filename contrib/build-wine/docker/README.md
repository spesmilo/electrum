Deterministic Windows binaries with Docker
==========================================

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
    $ sudo docker build --no-cache -t electrum-ltc-wine-builder-img contrib/build-wine/docker
    ```

    Note: see [this](https://stackoverflow.com/a/40516974/7499128) if having dns problems

3. Build Windows binaries

    ```
    $ git checkout $REV
    $ sudo docker run \
        --name electrum-ltc-wine-builder-cont \
        -v $PWD:/opt/wine64/drive_c/electrum-ltc \
        --rm \
        --workdir /opt/wine64/drive_c/electrum-ltc/contrib/build-wine \
        electrum-ltc-wine-builder-img \
        ./build.sh
    ```
4. The generated binaries are in `./contrib/build-wine/dist`.



Note: the `setup` binary (NSIS installer) is not deterministic yet.
