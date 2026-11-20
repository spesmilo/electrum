from pythonforandroid.recipes.sqlite3 import Sqlite3Recipe


assert Sqlite3Recipe._version == "3.50.4"
assert Sqlite3Recipe.depends == []
assert Sqlite3Recipe.python_depends == []


class Sqlite3RecipePinned(Sqlite3Recipe):
    version = "3.54.1"
    # The built-in recipe runs "./configure --disable-tcl" and "make", which needs the full
    # source tree: the sqlite.org amalgamation zip has no configure script, and the configure
    # script of the sqlite.org "autoconf" tarball rejects --disable-tcl.
    url = 'https://github.com/sqlite/sqlite/archive/refs/tags/version-{version}.tar.gz'
    sha512sum = "1e83df5575df56b5ed79fea7e1c21550ee50c849bde6081d73d0fe2132039f9e88a325d6d9559047b0d4d463f3060c047b27fbb5f686b42d6785b5fbc375e5a6"


recipe = Sqlite3RecipePinned()
