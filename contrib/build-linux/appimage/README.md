AppImage binary for Electrum
============================

✓ _This binary should be reproducible, meaning you should be able to generate
   binaries that match the official releases._

This assumes an Ubuntu host, but it should not be too hard to adapt to another
similar system. The host architecture should be x86_64 (amd64).

We currently only build a single AppImage, for x86_64 architecture.
Help to adapt these scripts to build for (some flavor of) ARM would be welcome,
see [issue #5159](https://github.com/spesmilo/electrum/issues/5159).


1. Install Docker

    See `contrib/docker_notes.md`.

2. Build binary

    ```
    $ ./build.sh
    ```
    If you want reproducibility, try instead e.g.:
    ```
    $ ELECBUILD_COMMIT=HEAD ELECBUILD_NOCACHE=1 ./build.sh
    ```

3. The generated binary is in `./dist`.


## FAQ

### How can I see what is included in the AppImage?
Execute the binary as follows: `./electrum*.AppImage --appimage-extract`

### How to investigate diff between binaries if reproducibility fails?
```
cd dist/
./electrum-*-x86_64.AppImage1 --appimage-extract
mv squashfs-root/ squashfs-root1/
./electrum-*-x86_64.AppImage2 --appimage-extract
mv squashfs-root/ squashfs-root2/
$(cd squashfs-root1; find -type f -exec sha256sum '{}' \; > ./../sha256sum1)
$(cd squashfs-root2; find -type f -exec sha256sum '{}' \; > ./../sha256sum2)
diff sha256sum1 sha256sum2 > d
cat d
```

For file metadata, e.g. timestamps:
```
rsync -n -a -i --delete squashfs-root1/ squashfs-root2/
```

Useful binary comparison tools:
- vbindiff
- diffoscope
