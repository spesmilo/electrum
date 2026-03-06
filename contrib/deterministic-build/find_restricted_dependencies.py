#!/usr/bin/env python3
import sys
from importlib.metadata import requires, PackageNotFoundError

def is_dependency_edge_blacklisted(*, parent_pkg: str, dep: str) -> bool:
    """Sometimes a package declares a hard dependency
    for some niche functionality that we really do not care about.
    """
    dep = dep.lower()
    parent_pkg = parent_pkg.lower()
    return (parent_pkg, dep) in {
        ("qrcode", "colorama"),  # only needed for using qrcode-CLI on Windows.
        ("click",  "colorama"),  # 'click' is a CLI tool, and it only needs colorama on Windows.
                                 # In fact, we should blacklist 'click' itself, but that should be done elsewhere.
    }


def check_restriction(*, dep: str, restricted: str, parent_pkg: str):
    # See: https://www.python.org/dev/peps/pep-0496/
    # Hopefully we don't need to parse the whole microlanguage
    if is_dependency_edge_blacklisted(dep=dep, parent_pkg=parent_pkg):
        return False
    if "extra" in restricted and "[" not in dep:
        return False
    for marker in ["os_name", "platform_release", "sys_platform", "platform_system"]:
        if marker in restricted:
            return True
    return False


def main():
    for p in sys.stdin.read().split():
        p = p.strip()
        if not p:
            continue
        assert "==" in p, "This script expects a list of packages with pinned version, e.g. package==1.2.3, not {}".format(p)
        pkg_name, _ = p.rsplit("==", 1)
        try:
            reqs = requires(pkg_name)
        except PackageNotFoundError:
            raise Exception("Package not found in this environment: {}. Install it first.".format(p))
        if reqs is None:
            continue
        for r in reqs:
            if ";" not in r:
                continue
            # example value for "r": "pefile (>=2017.8.1) ; sys_platform == \"win32\""
            dep, restricted = r.split(";", 1)
            dep = dep.strip()
            restricted = restricted.strip()
            dep_basename = dep.split(" ")[0]
            if check_restriction(dep=dep, restricted=restricted, parent_pkg=pkg_name):
                print(dep_basename, sep=" ")
                print("Installing {} from {} although it is only needed for {}".format(dep, pkg_name, restricted), file=sys.stderr)

if __name__ == "__main__":
    main()
