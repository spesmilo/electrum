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

2. Build image and binaries

    ```
    $ sudo docker build -f contrib/build-wine/docker/Dockerfile .
    ```

    Note: see [this](https://stackoverflow.com/a/40516974/7499128) if having dns problems

3. The generated binaries are in `./contrib/build-wine/dist` inside the container.

4. Generated binaries will also be published as a GitHub release if the following environment variables are set:

      ```
      GITHUB_RELEASE_TAG
      GITHUB_RELEASE_COMMIT
      GITHUB_RELEASE_REPOSITORY
      GITHUB_RELEASE_ACCESS_TOKEN
      ```


Note: the `setup` binary (NSIS installer) is not deterministic yet.
