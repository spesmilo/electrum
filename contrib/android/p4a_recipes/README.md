python-for-android local recipes
--------------------------------

These folders are recipes (build scripts) for most of our direct and transitive
dependencies for the Android app. python-for-android has recipes built-in for
many packages but it also allows users to specify their "local" recipes.
Local recipes have precedence over the built-in recipes.

The local recipes we have here are mostly just used to pin down specific
versions and hashes for reproducibility. The hashes are updated manually.

The Android QML scanner uses the `libzxing` recipe to build zxing-cpp's QR
decoder and C API. Camera capture is handled by Qt Multimedia. Desktop builds
continue to use zbar.

For testing the ctypes wrapper on Linux/macOS, run `./contrib/make_zxing.sh`
from the repository root (requires CMake and a C++20 compiler), then run
`python -m pytest tests/test_qrreader.py`. The script places a native shared
library in `electrum/`; it does not change the desktop scanner's selection.
