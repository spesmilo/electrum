import pybitcointools
import sys


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        priv_key = sys.argv[1]#"LmB72UZvRmJ5cUPZWpxqYWW5KkCgASa53GZQNhWNTPzJ9J1R4T8x"
        priv_data = pybitcointools.decode_privkey(priv_key)
        print(pybitcointools.encode_privkey(priv_data, "wif_compressed"))
        print(pybitcointools.privtoaddr(priv_key))
    else:
        print("Usage: %s [private_key]" % sys.argv[0])

