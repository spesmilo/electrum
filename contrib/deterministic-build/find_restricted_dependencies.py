#!/usr/bin/env python3
import sys

try:
    import requests
except ImportError as e:
    sys.exit(f"Error: {str(e)}. Try 'sudo python3 -m pip install <module-name>'")


def check_restriction(p, r):
    # See: https://www.python.org/dev/peps/pep-0496/
    # Hopefully we don't need to parse the whole microlanguage
    if "extra" in r and "[" not in p:
        return False
    for marker in ["os_name", "platform_release", "sys_platform", "platform_system"]:
        if marker in r:
            return True


for p in sys.stdin.read().split():
    p = p.strip()
    if not p:
        continue
    assert "==" in p, "This script expects a list of packages with pinned version, e.g. package==1.2.3, not {}".format(p)
    p, v = p.rsplit("==", 1)
    try:
        data = requests.get("https://pypi.org/pypi/{}/{}/json".format(p, v)).json()["info"]
    except ValueError:
        raise Exception("Package could not be found: {}=={}".format(p, v))
    try:
        for r in data["requires_dist"]:
            if ";" not in r:
                continue
            d, restricted = r.split(";", 1)
            if check_restriction(d, restricted):
                print(d, sep=" ")
                print("Installing {} from {} although it is only needed for {}".format(d, p, restricted), file=sys.stderr)
    except TypeError:
        # Has no dependencies at all
        continue

