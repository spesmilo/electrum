# libsecp256k1-0 for Electron Cash
## Mini HOW-TO

![CodeIcon](https://img.icons8.com/color/96/000000/smartphone-cpu.png)

If you have gotten to this page, likely you have been sent here by Electron Cash's  dialog informing you that you don't have **libsecp** installed.  The purpose of this document is to instruct you on how to rectify the situation.

### About libsecp256k1-0

This library was originally developed by [Peter Wuille](https://twitter.com/pwuille?lang=en) for Bitcoin, and has since been adapted and used in many major cryptocurrencies for fast elliptic curve operations.  Electron Cash uses this library as a secure way to sign and verify transactions.

### CashShuffle requires libsecp256k1-0

Electron Cash's [CashShuffle](https://www.cashshuffle.com) makes heavy use elliptic curve cryptography with each message sent.  Since Python-only cryptography is incredibly slow (and potentially susceptible to side-channel exploits), libsecp is required for [CashShuffle](https://www.cashshuffle.com) within Electron Cash.  The reason for this requirement is simple: you would be interfering with the speed and security of other shufflers by *not* using libsecp. Thus in order to be a reliable partner for other shuffle participants, Electron Cash requires you to use this library if you want to enable [CashShuffle](https://www.cashshuffle.com).

### Using libsecp with Electron Cash

You have a few options:

  - If on **Windows**, it's recommended you run one of the [release .exe files available here](https://www.electroncash.org/#download). The library is included in the `.exe`.
  - If on **macOS**, it's recommended you install Electron Cash from the [release .dmg available here](https://www.electroncash.org/#download). The library is included in the `.app` bundle.
  - For **Linux x86_64** (the most common architecture), the Electron Cash [release srcdist .tar.gz available here](https://www.electroncash.org/#download) should have the library pre-compiled and living in the `electroncash/` subfolder of the tarball. You can simply run Electron Cash "from source" (which, paradoxically, does include a compiled library embedded within it), and it should work.
  - For other architectures and/or Unixey OS's, or if running from *git head* then proceed to the sections below.

### If running from github head -- dev mode ;)

   - `git clone` the latest git head from [https://github.com/Electron-Cash/Electron-Cash](https://github.com/Electron-Cash/Electron-Cash) (or `git pull` from master if you already  have it cloned).
   - run the script `contrib/make_secp`
   - **Done!** If all goes well, `libsecp256k1` should low live alongside the Python files in the `electroncash/` subfolder of Electron Cash.  If not, make sure you have a C-compiler installed on the system as well as automake, and libtool installed and try again.

### If you are running from the "srcdist" (.tar.gz) but the provided .so file doesn't work...

Chances are you either are on an exotic architecture (such as 32 bit Intel, non-x86_64, etc) or are on a non-Linux Unix such as BSD, HURD, etc.  Don't despair! You can still get this working provided the below preconditions are met:

- You must be on a "Unix-like" OS that can execute Bash scripts and/or run `configure` scripts successfully.  Windows using MSYS should work fine (but admitedly is untested by us).
- You must have a C compiler, automake, & libtool installed.
- You must have git installed.

The steps are as follows:

   - You will need to `git clone` the repository from [https://github.com/Electron-Cash/Electron-Cash](https://github.com/Electron-Cash/Electron-Cash)
   - Proceed to the **"github head"** section above.

### Last resort: Try your package manager

We say this is a last resort because in the future Electron Cash will benefit from the customized *[Bitcoin ABC](https://github.com/Bitcoin-ABC/bitcoin-abc/tree/master/src/secp256k1)* based libsecp we provide (with the Schnorr signature module enabled).  But for now, your package manager's `libsecp256k1-0` will be sufficient.  *Note: Not all distributions provide this library as a package, so your mileage may vary.*

Example Ubuntu command:
```
$ sudo apt install libsecp256k1-0
```

#### The above all failed! What now?!

[Open an issue](https://github.com/Electron-Cash/Electron-Cash/issues) in our github issue tracker.
