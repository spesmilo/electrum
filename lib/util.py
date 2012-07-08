import os
import platform
import sys

def print_error(*args):
    for item in args:
      sys.stderr.write(str(item))

    sys.stderr.write("\n")
    sys.stderr.flush()

def appdata_dir():
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

