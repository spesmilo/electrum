# Notes about using Docker in the build scripts

- To install Docker:

    This assumes an Ubuntu (x86_64) host, but it should not be too hard to adapt to another similar system.

    ```
    $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    $ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    $ sudo apt-get update
    $ sudo apt-get install -y docker-ce
    ```

- To communicate with the docker daemon, the build scripts either need to be called via sudo,
  or the unix user on the host system (e.g. the user you run as) needs to be
  part of the `docker` group. i.e.:
  ```
  $ sudo usermod -aG docker ${USER}
  ```
  (and then reboot or similar for it to take effect)
  
