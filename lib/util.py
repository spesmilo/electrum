import os, sys, re, json
import platform
import shutil
from datetime import datetime
is_verbose = False


class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        from transaction import Transaction
        if isinstance(obj, Transaction): 
            return obj.as_dict()
        return super(MyEncoder, self).default(obj)


def set_verbosity(b):
    global is_verbose
    is_verbose = b

def print_error(*args):
    if not is_verbose: return
    args = [str(item) for item in args]
    sys.stderr.write(" ".join(args) + "\n")
    sys.stderr.flush()

def print_msg(*args):
    # Stringify args
    args = [str(item) for item in args]
    sys.stdout.write(" ".join(args) + "\n")
    sys.stdout.flush()

def print_json(obj):
    try:
        s = json.dumps(obj, sort_keys = True, indent = 4, cls=MyEncoder)
    except TypeError:
        s = repr(obj)
    sys.stdout.write(s + "\n")
    sys.stdout.flush()
    

def user_dir():
    if "HOME" in os.environ:
        return os.path.join(os.environ["HOME"], ".electrum")
    elif "APPDATA" in os.environ:
        return os.path.join(os.environ["APPDATA"], "Electrum")
    elif "LOCALAPPDATA" in os.environ:
        return os.path.join(os.environ["LOCALAPPDATA"], "Electrum")
    elif 'ANDROID_DATA' in os.environ:
        return "/sdcard/electrum/"
    else:
        #raise Exception("No home directory found in environment variables.")
        return 

def appdata_dir():
    """Find the path to the application data directory; add an electrum folder and return path."""
    if platform.system() == "Windows":
        return os.path.join(os.environ["APPDATA"], "Electrum")
    elif platform.system() == "Linux":
        return os.path.join(sys.prefix, "share", "electrum")
    elif (platform.system() == "Darwin" or
          platform.system() == "DragonFly" or
          platform.system() == "OpenBSD" or
	  platform.system() == "NetBSD"):
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


def format_satoshis(x, is_diff=False, num_zeros = 0, decimal_point = 8, whitespaces=False):
    from decimal import Decimal
    s = Decimal(x)
    sign, digits, exp = s.as_tuple()
    digits = map(str, digits)
    while len(digits) < decimal_point + 1:
        digits.insert(0,'0')
    digits.insert(-decimal_point,'.')
    s = ''.join(digits).rstrip('0')
    if sign: 
        s = '-' + s
    elif is_diff:
        s = "+" + s

    p = s.find('.')
    s += "0"*( 1 + num_zeros - ( len(s) - p ))
    if whitespaces:
        s += " "*( 1 + decimal_point - ( len(s) - p ))
        s = " "*( 13 - decimal_point - ( p )) + s 
    return s


# Takes a timestamp and returns a string with the approximation of the age
def age(from_date, since_date = None, target_tz=None, include_seconds=False):
    if from_date is None:
        return "Unknown"

    from_date = datetime.fromtimestamp(from_date)
    if since_date is None:
        since_date = datetime.now(target_tz)

    distance_in_time = since_date - from_date
    distance_in_seconds = int(round(abs(distance_in_time.days * 86400 + distance_in_time.seconds)))
    distance_in_minutes = int(round(distance_in_seconds/60))

    if distance_in_minutes <= 1:
        if include_seconds:
            for remainder in [5, 10, 20]:
                if distance_in_seconds < remainder:
                    return "less than %s seconds ago" % remainder
            if distance_in_seconds < 40:
                return "half a minute ago"
            elif distance_in_seconds < 60:
                return "less than a minute ago"
            else:
                return "1 minute ago"
        else:
            if distance_in_minutes == 0:
                return "less than a minute ago"
            else:
                return "1 minute ago"
    elif distance_in_minutes < 45:
        return "%s minutes ago" % distance_in_minutes
    elif distance_in_minutes < 90:
        return "about 1 hour ago"
    elif distance_in_minutes < 1440:
        return "about %d hours ago" % (round(distance_in_minutes / 60.0))
    elif distance_in_minutes < 2880:
        return "1 day ago"
    elif distance_in_minutes < 43220:
        return "%d days ago" % (round(distance_in_minutes / 1440))
    elif distance_in_minutes < 86400:
        return "about 1 month ago"
    elif distance_in_minutes < 525600:
        return "%d months ago" % (round(distance_in_minutes / 43200))
    elif distance_in_minutes < 1051200:
        return "about 1 year ago"
    else:
        return "over %d years ago" % (round(distance_in_minutes / 525600))




# URL decode
_ud = re.compile('%([0-9a-hA-H]{2})', re.MULTILINE)
urldecode = lambda x: _ud.sub(lambda m: chr(int(m.group(1), 16)), x)

def parse_url(url):
    from decimal import Decimal
    url = str(url)
    o = url[8:].split('?')
    address = o[0]
    if len(o)>1:
        params = o[1].split('&')
    else:
        params = []

    amount = label = message = signature = identity = ''
    for p in params:
        k,v = p.split('=')
        uv = urldecode(v)
        if k == 'amount': 
            amount = uv
            m = re.match('([0-9\.]+)X([0-9])', uv)
            if m:
                k = int(m.group(2)) - 8 
                amount = Decimal(m.group(1)) * pow(  Decimal(10) , k)
            else:
                amount = Decimal(uv)
        elif k == 'message': 
            message = uv
        elif k == 'label': 
            label = uv
        elif k == 'signature':
            identity, signature = uv.split(':')
            url = url.replace('&%s=%s'%(k,v),'')
        else: 
            print k,v

    return address, amount, label, message, signature, identity, url


# Python bug (http://bugs.python.org/issue1927) causes raw_input
# to be redirected improperly between stdin/stderr on Unix systems
def raw_input(prompt=None):
    if prompt:
        sys.stdout.write(prompt)
    return builtin_raw_input()
import __builtin__
builtin_raw_input = __builtin__.raw_input
__builtin__.raw_input = raw_input
