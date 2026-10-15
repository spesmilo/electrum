import sys, tempfile, subprocess
from pathlib import Path
from importlib.metadata import distribution


PYPROJECT_TOML = """
[project]
name = "{name}"
version = "{version}"
description = "Ghost package to satisfy dependencies"
"""


def install_ghost(name: str, version: str) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        pyproject_toml = PYPROJECT_TOML.format(name=name, version=version)
        (Path(tmpdir) / "pyproject.toml").write_text(pyproject_toml)
        subprocess.check_call([sys.executable, "-m", "pip", "install", tmpdir])

        dist = distribution(name)
        for file in dist.files:
            path = file.locate()
            if path.name == "direct_url.json":
                path.unlink()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python install_ghost.py <package name>==<package version>")
        sys.exit(1)
    name, version = sys.argv[1].split("==")
    install_ghost(name, version)
