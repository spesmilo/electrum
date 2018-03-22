def alias_import(hooks_api, pkg_name, alias):
    """imp imports a given package `pkg_name` using the name `alias`.

    To avoid rewriting the import statements (yields smaller diff against
    upstream and thus easier rebasing) but still avoid package conflicts with
    upstream, electrum-ftc is 'aliasing' the pkg names at runtime by
    manipulating sys.modules. This approach confuses PyInstaller because
    it tries to conventionally import the modules it encounters during the
    analysis of the python bytecode instead of just checking the module's
    `__file__` attribute. Consequently, this helper function can be used
    by PyInstaller hooks to import the package by its actual name and
    then rename it in the underlying import dependency graph such that
    PyInstaller is then able to match it with what it found during byte code
    analysis.

    The downside is that once the analysis is finished the module names
    need to be written back to their actual names such that everything
    is packaged properly for the runtime. This is being done by processing
    the `pure` field in the spec file.

    PyInstaller features that don't work:

     * `add_alias_module()` in the `pre_safe_import_module.py`-hook didn't
       work for modules that are imported inside a method (e.g. `qrscanner`)
       because only modules of type `Package` (and not `AliasNode`) will be
       processed further:
       https://github.com/pyinstaller/pyinstaller/blob/6d91c16551c837d80de3e0e8f236b08bec7ab02f/PyInstaller/lib/modulegraph/modulegraph.py#L2351
       This is most likely a bug. Once fixed and released, `add_alias_module()`
       should replace alias_import().

     * Also overriding the module name is currently not possible
       https://github.com/pyinstaller/pyinstaller/commit/b246216340c3197d58558642acfa946a7d5c1418
       even though there is code that assumes otherwise
       https://github.com/pyinstaller/pyinstaller/blob/6d91c16551c837d80de3e0e8f236b08bec7ab02f/PyInstaller/depend/analysis.py#L262-L265
       However, even if this would be fixed it wouldn't help with the aliasing
       issue because a hook is only executed once and thus for repeated execution
       of this code path the module name wouldn't be overridden again.
    """

    hooks_api.module_graph.import_hook(pkg_name)
    graph = hooks_api.module_graph.graph
    for old_node_name in list(graph.nodes.keys()):
        if not isinstance(old_node_name, str):
            continue
        new_node_name = old_node_name.replace(pkg_name, alias)
        node = graph.nodes.pop(old_node_name)
        node[2].graphident = node[2].identifier = new_node_name
        graph.nodes[new_node_name] = node
    for k, v in graph.edges.items():
        graph.edges[k] = (
            v[0].replace(pkg_name, alias) if isinstance(v[0], str) else v[0],
            v[1].replace(pkg_name, alias),
            *v[2:],
        )

def pre_safe_import_module(api):
    alias_import(api, 'electrum_ftc', 'electrum')
