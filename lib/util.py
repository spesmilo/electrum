import os
import platform
import sys

def print_error(*args):
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
      raise BaseException("No home directory found in environment variables.")

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

