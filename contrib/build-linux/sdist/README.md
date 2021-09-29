Source tarballs
===============

✓ _This file should be reproducible, meaning you should be able to generate
   distributables that match the official releases._

This assumes an Ubuntu (x86_64) host, but it should not be too hard to adapt to another
similar system.

1. Install Docker

    ```
    $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    $ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    $ sudo apt-get update
    $ sudo apt-get install -y docker-ce
    ```

2. Build source tarball

    ```
    $ ./build.sh
    ```
    If you want reproducibility, try instead e.g.:
    ```
    $ ELECBUILD_COMMIT=HEAD ELECBUILD_NOCACHE=1 ./build.sh
    ```

3. The generated distributables are in `./dist`.
