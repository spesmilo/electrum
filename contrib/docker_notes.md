# Using the build scripts

Most of our build scripts are docker-based.
(All, except the macOS build, which is a separate beast and always has to be special-cased
at the cost of significant maintenance burden...)

Typically, the build flow is:

- build a docker image, based on debian
  - the apt sources mirror used is `snapshot.debian.org`
    - (except for the source tarball build, which is simple enough not to need this)
    - this helps with historical reproducibility
    - note that `snapshot.debian.org` is often slow and sometimes keeps timing out :/
      (see #8496)
      - a potential alternative would be `snapshot.notset.fr`, but that mirror is missing
        e.g. `binary-i386`, which is needed for the wine/windows build.
    - if you are just trying to build for yourself and don't need reproducibility,
      you can just switch back to the default debian apt sources mirror.
  - docker caches the build (locally), and so this step only needs to be rerun
    if we update the Dockerfile. This caching happens automatically and by default.
    - you can disable the caching by setting envvar `ELECBUILD_NOCACHE=1`. See below.
- create a docker container from the image, and build the final binary inside the container


## Notes about using Docker

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


## Environment variables

- `ELECBUILD_COMMIT`

    When unset or empty, we build directly from the local git clone. These builds
    are *not* reproducible.

    When non-empty, it should be set to a git ref. We will create a fresh git clone
    checked out at that reference in `/tmp/electrum_build/`, and build there.

- `ELECBUILD_NOCACHE=1`

    A non-empty value forces a rebuild of the docker image.

    Before we started using `snapshot.debian.org` for apt sources,
    setting this was necessary to properly test historical reproducibility.
    (we were version-pinning packages installed using `apt`, but it was not realistic to
     version-pin all transitive dependencies, and sometimes an update of those resulted in
     changes to our binary builds)

    I think setting this is no longer necessary for building reproducibly.

