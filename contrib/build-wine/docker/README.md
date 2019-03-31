Deterministic Windows binaries with Docker
==========================================

Produced binaries are deterministic, so you should be able to generate
binaries that match the official releases.

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
    $ sudo docker build -t electroncash-wine-builder-img contrib/build-wine/docker
    ```

    _Note 1:_ see [this](https://stackoverflow.com/a/40516974/7499128) if having dns problems

    _Note 2:_ If you are using a MacOS host, run the above **without** `sudo`.

3. Build Windows binaries

    It's recommended to build from a fresh clone
    (but you can skip this if reproducibility is not necessary).

    ```
    $ FRESH_CLONE=contrib/build-wine/fresh_clone && \
        rm -rf $FRESH_CLONE && \
        mkdir -p $FRESH_CLONE && \
        cd $FRESH_CLONE  && \
        git clone https://github.com/Electron-Cash/Electron-Cash && \
        cd Electron-Cash
    ```

    And then build from this directory:
    ```
    $ REV=4.0.0  # Replace this with whatever Electron Cash revision tag you want to build
    $ git checkout $REV
    $ sudo docker run -it \
        --name electroncash-wine-builder-cont \
        -v $PWD:/opt/wine64/drive_c/electrum \
        --rm \
        --workdir /opt/wine64/drive_c/electrum/contrib/build-wine \
        electroncash-wine-builder-img \
        ./_build.sh $REV
    ```

    _Note:_ If you are on a MacOS host, you should run the above command **without** `sudo`.

4. The generated binaries are in `./contrib/build-wine/dist` (relative to the `fresh_clone/Electron-Cash` directory you should find yourself in if you followed 1-3 above).



Note: the `setup` binary (NSIS installer) is not deterministic yet.
