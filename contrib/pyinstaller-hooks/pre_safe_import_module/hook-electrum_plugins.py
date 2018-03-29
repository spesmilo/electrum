def pre_safe_import_module(api):
    from importlib.machinery import SourceFileLoader
    from pathlib import Path
    alias_import = SourceFileLoader(
        "alias_import",
        str(Path(__file__).parent.joinpath("alias_import.py"))).load_module()
    alias_import.imp(api, 'electrum_ftc_plugins', 'electrum_plugins')
