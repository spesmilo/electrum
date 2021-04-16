Source tarballs
===============

✓ _This file should be reproducible, meaning you should be able to generate
   distributables that match the official releases._

This assumes an Ubuntu (x86_64) host, but it should not be too hard to adapt to another
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
    $ sudo docker build -t electrum-sdist-builder-img contrib/build-linux/sdist
    ```

3. Build source tarballs

    It's recommended to build from a fresh clone
    (but you can skip this if reproducibility is not necessary).

    ```
    $ FRESH_CLONE=contrib/build-linux/sdist/fresh_clone && \
        sudo rm -rf $FRESH_CLONE && \
        umask 0022 && \
        mkdir -p $FRESH_CLONE && \
        cd $FRESH_CLONE  && \
        git clone https://github.com/spesmilo/electrum.git && \
        cd electrum
    ```

    And then build from this directory:
    ```
    $ git checkout $REV
    $ sudo docker run -it \
        --name electrum-sdist-builder-cont \
        -v $PWD:/opt/electrum \
        --rm \
        --workdir /opt/electrum/contrib/build-linux/sdist \
        electrum-sdist-builder-img \
        ./build.sh
    ```
4. The generated distributables are in `./dist`.
