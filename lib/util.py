import os, sys
import platform

is_verbose = True

def set_verbosity(b):
    global is_verbose
    is_verbose = b

def print_error(*args):
    if not is_verbose: return
    print_msg(args)

def print_msg(*args):
    # Stringify args
    args = [str(item) for item in args]
    sys.stderr.write(" ".join(args) + "\n")
    sys.stderr.flush()


def user_dir():
    if "HOME" in os.environ:
        return os.path.join(os.environ["HOME"], ".electrum")
    elif "LOCALAPPDATA" in os.environ:
        return os.path.join(os.environ["LOCALAPPDATA"], "Electrum")
    elif "APPDATA" in os.environ:
        return os.path.join(os.environ["APPDATA"], "Electrum")
    else:
        #raise BaseException("No home directory found in environment variables.")
        return 

def appdata_dir():
    """Find the path to the application data directory; add an electrum folder and return path."""
    if platform.system() == "Windows":
        return os.path.join(os.environ["APPDATA"], "Electrum")
    elif platform.system() == "Linux":
        return os.path.join(sys.prefix, "share", "electrum")
    elif (platform.system() == "Darwin" or
          platform.system() == "DragonFly"):
        return "/Library/Application Support/Electrum"
    else:
        raise Exception("Unknown system")


def get_resource_path(*args):
    return os.path.join(".", *args)


def local_data_dir():
    """Return path to the data folder."""
    assert sys.argv
    prefix_path = os.path.dirname(sys.argv[0])
    local_data = os.path.join(prefix_path, "data")
    return local_data


def format_satoshis(x, is_diff=False, num_zeros = 0):
    from decimal import Decimal
    s = Decimal(x)
    sign, digits, exp = s.as_tuple()
    digits = map(str, digits)
    while len(digits) < 9:
        digits.insert(0,'0')
    digits.insert(-8,'.')
    s = ''.join(digits).rstrip('0')
    if sign: 
        s = '-' + s
    elif is_diff:
        s = "+" + s

    p = s.find('.')
    s += "0"*( 1 + num_zeros - ( len(s) - p ))
    s += " "*( 9 - ( len(s) - p ))
    s = " "*( 5 - ( p )) + s
    return s
