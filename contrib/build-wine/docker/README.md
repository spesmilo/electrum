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

2. Build Windows binaries

    ```
    $ git checkout $REV
    $ sudo docker build --no-cache -t electrum-img -f contrib/build-wine/docker/Dockerfile .
    ```

    Note: see [this](https://stackoverflow.com/a/40516974/7499128) if having dns problems


3. The generated binaries can be easily extracted
    ```
    $ sudo docker run --rm --detach --name tmp_electrum -i electrum-img
    $ sudo docker cp tmp_electrum:/opt/wine64/drive_c/electrum/contrib/build-wine/dist .
    $ sudo docker stop tmp_electrum
    $ ls ./dist
    ```

Note: the `setup` binary (NSIS installer) is not deterministic yet.
