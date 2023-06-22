# Source tarballs

✓ _This file should be reproducible, meaning you should be able to generate
   distributables that match the official releases._

This assumes an Ubuntu (x86_64) host, but it should not be too hard to adapt to another
similar system.

We distribute two tarballs, a "normal" one (the default, recommended for users),
and a strictly source-only one (for Linux distro packagers).
The normal tarball, in addition to including everything from
the source-only one, also includes:
- compiled (`.mo`) locale files (in addition to source `.po` locale files)
- compiled (`_pb2.py`) protobuf files (in addition to source `.proto` files)
- the `packages/` folder containing source-only pure-python runtime dependencies


## Build steps

1. Install Docker

    See [`contrib/docker_notes.md`](../../docker_notes.md).

    (worth reading even if you already have docker)

2. Build tarball

    (set envvar `OMIT_UNCLEAN_FILES=1` to build the "source-only" tarball)
    ```
    $ ./build.sh
    ```
    If you want reproducibility, try instead e.g.:
    ```
    $ ELECBUILD_COMMIT=HEAD ELECBUILD_NOCACHE=1 ./build.sh
    $ ELECBUILD_COMMIT=HEAD ELECBUILD_NOCACHE=1 OMIT_UNCLEAN_FILES=1 ./build.sh
    ```

3. The generated distributables are in `./dist`.
