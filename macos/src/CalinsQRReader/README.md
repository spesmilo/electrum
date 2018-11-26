# Calin's QR Reader

Author: Calin Culianu <calin.culianu@gmail.com>

---

A helper app for Electron Cash. This app emulates the 'zbar' functionality present on Windows and Linux for Electron Cash.

It is a very small and lightweight app with no external dependencies other than what macOS provides in its own system libs for
reading from the camera and detecting QR codes in video.

The app basically creates a window and reads from the default camera device on the system. It will continue to run until either
the window is closed by the user or a QR image is read.

1. If a QR image is scanned, it will print the decoded string to stdout and exit.
2. If there is an error detecting the camera, it will show an error message and wait.
3. If the user closes the window without having scanned a QR code (because of an error or s/he changed his/her mind),
it will print nothing to stdout and exit.

---

### Building

In order to build the app and have it actually work on deployed machines other than your developer machine, you need an Apple Developer Certificate (you have to join the Apple developer program), and you need to sign the app. Otherwise on newer macOS, camera access won't be granted to the app.

1. Load included source code in Xcode.
2. Hit build.

Or, if you prefer the command-line:

1. Chdir to sources
2. `xcodebuild`
3. `codesign -v -f -s MY_DEVELOPER_CERT build/Release/CalinsQRReader.app`


### See Also

- `lib/qrscanner.py` - for how it is integrated into Electron Cash.
- `contrib/build-osx/osx.spec` - for how it's collected and put into the final Electron-Cash.app.
- `macos/compiled/CalinsQRReader.app` - the compiled and developer signed version of this app, which is what gets executed by `qrscanner.py`
