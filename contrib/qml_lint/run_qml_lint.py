#!/usr/bin/env python3
#
# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
#
# This script runs qmllint over the QML sources of the QML GUI and of the
# plugins. See https://github.com/spesmilo/electrum/issues/10802
#
# The types of the 'org.electrum' QML module are registered from Python at
# runtime (see qeapp.py), so qmllint cannot resolve the module on its own.
# This script generates a minimal qmldir + qmltypes stub for the module into a
# temporary directory and passes it to qmllint via '-I'. With the module
# resolvable, a misspelled type name fails the lint (with a "did you mean"
# suggestion) instead of drowning in unresolved-import noise.
#
# Which warning categories gate CI is configured in .qmllint.ini at the repo
# root; qmllint discovers that file by walking up from each linted file.
#
# qmllint is not distributed with PyQt6; we take it from the PySide6 wheels
# (PySide6-Addons is needed for the QtMultimedia types used by QRScan.qml).
# The pinned install command lives in the 'qml-lint' job in
# .github/workflows/tests.yml -- that is the single version authority.
#
# If CI fails with "[import]" errors on valid 'org.electrum' types, the likely
# cause is a registration in qeapp.py that this script's regex did not match.
#
# If CI fails with "[unqualified]" on a name that is correct, see
# is_known_identifier() and DYNAMIC_SCOPE_NAMES below.

import collections
import json
import os
import os.path
import re
import subprocess
import sys
import tempfile

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(project_root)

QEAPP_PATH = "electrum/gui/qml/qeapp.py"

# properties of the root window in main.qml, reachable everywhere via dynamic scoping
ROOT_WINDOW_NAMES = {"app", "constants"}
# implicitly injected into delegates by the views
DELEGATE_NAMES = {"index", "model", "modelData", "section"}
# Remaining names qmllint reports as unknown, per file, in code that predates this
# lint. Not each one was confirmed at runtime; they are of these kinds:
# - names from the scope of whichever file instantiates this one,
# - signal handler parameters and properties of the enclosing object,
# - signal handlers on org.electrum objects, as the stub types declare no signals.
# Do not add to this for new code: qualify the name instead (e.g. with an id).
# An entry that is no longer needed fails the lint, so this list can only shrink.
DYNAMIC_SCOPE_NAMES = {
    "electrum/gui/qml/components/About.qml": {"link"},
    "electrum/gui/qml/components/AddressDetails.qml": {"onAddressDeleteFailed", "onAuthRequired", "onFrozenChanged", "onLabelChanged"},
    "electrum/gui/qml/components/ChannelDetails.qml": {"onTrampolineFrozenInGossipMode"},
    "electrum/gui/qml/components/CloseChannelDialog.qml": {"onAuthRequired", "onChannelChanged", "onChannelCloseFailed", "onChannelCloseSuccess"},
    "electrum/gui/qml/components/ConfirmTxDialog.qml": {"doAccept"},
    "electrum/gui/qml/components/CpfpBumpFeeDialog.qml": {"doAccept"},
    "electrum/gui/qml/components/ExceptionDialog.qml": {"close"},
    "electrum/gui/qml/components/ImportAddressesKeysDialog.qml": {"doAccept"},
    "electrum/gui/qml/components/InvoiceDialog.qml": {"mainView"},
    "electrum/gui/qml/components/LightningPaymentDetails.qml": {"onLabelChanged"},
    "electrum/gui/qml/components/MessageDialog.qml": {"doAccept", "doReject"},
    "electrum/gui/qml/components/OpenChannelDialog.qml": {"onAuthRequired", "onChannelOpenError", "onChannelOpenSuccess", "onChannelOpening", "onConflictingBackup", "onFinalizerChanged", "onValidationError"},
    "electrum/gui/qml/components/RbfBumpFeeDialog.qml": {"doAccept"},
    "electrum/gui/qml/components/RbfCancelDialog.qml": {"doAccept"},
    "electrum/gui/qml/components/ReceiveDetailsDialog.qml": {"doAccept"},
    "electrum/gui/qml/components/ReceiveDialog.qml": {"onStatusChanged", "status"},
    "electrum/gui/qml/components/ScanDialog.qml": {"doReject"},
    "electrum/gui/qml/components/SwapDialog.qml": {"_swaphelper"},
    "electrum/gui/qml/components/TxDetails.qml": {"onConfirmRemoveLocalTx", "onLabelChanged"},
    "electrum/gui/qml/components/WalletMainView.qml": {"close", "getSerializedTx", "infobanner", "onFinished", "onInvoiceCreateError", "onInvoiceResolved", "onLnurlError", "onLnurlRetrieved", "onNeedsLNURLUserInput", "onRequestResolved", "onResolveError", "onSignError", "onValidationError", "onValidationSuccess", "onValidationWarning", "stack", "wallet"},
    "electrum/gui/qml/components/controls/HistoryItemDelegate.qml": {"visualModel"},
    "electrum/gui/qml/components/controls/ServerConnectModeComboBox.qml": {"server_connect_mode_cb"},
    "electrum/gui/qml/components/main.qml": {"onError", "onUndefinedNPub"},
    "electrum/gui/qml/components/wizard/WCConfirmSeed.qml": {"wizard"},
    "electrum/gui/qml/components/wizard/WCCreateSeed.qml": {"generatedSeed", "onGeneratedSeedChanged"},
    "electrum/gui/qml/components/wizard/WCEnterExt.qml": {"wiz"},
    "electrum/gui/qml/components/wizard/WCHaveMasterKey.qml": {"onValidationMessageChanged", "validationMessage", "wiz"},
    "electrum/gui/qml/components/wizard/WCHaveSeed.qml": {"checkIsLast", "wiz"},
    "electrum/gui/qml/components/wizard/WCScriptAndDerivation.qml": {"wiz"},
    "electrum/gui/qml/components/wizard/WCTermsOfUseRequest.qml": {"wiz"},
    "electrum/gui/qml/components/wizard/WCWelcome.qml": {"checkIsLast"},
    "electrum/gui/qml/components/wizard/WizardComponent.qml": {"wizard"},
    "electrum/plugins/psbt_nostr/qml/PsbtReceiveDialog.qml": {"doAccept", "doReject"},
    "electrum/plugins/trustedcoin/qml/KeepDisable.qml": {"checkIsLast"},
}


def find_qmllint() -> str:
    # Invoke the real qmllint binary bundled inside the PySide6 package, not the
    # 'pyside6-qmllint' wrapper: the wrapper exits 0 on its own argument errors.
    try:
        import PySide6
    except ImportError:
        sys.exit("error: PySide6 is not installed.\n"
                 "See the 'qml-lint' job in .github/workflows/tests.yml for the pinned\n"
                 "install command (PySide6-Essentials + PySide6-Addons).")
    exe_name = "qmllint.exe" if sys.platform == "win32" else "qmllint"
    exe_path = os.path.join(PySide6.__path__[0], exe_name)
    if not os.path.exists(exe_path):
        sys.exit(f"error: qmllint binary not found at {exe_path}")
    return exe_path


def get_registered_type_names() -> list:
    reg_re = re.compile(r"qmlRegisterType\(\w+, 'org\.electrum', 1, 0, '(\w+)'\)")
    names = []
    with open(QEAPP_PATH, "r", encoding="utf-8") as f:
        for line in f.read().splitlines():
            code = line.split("#", 1)[0]  # commented-out registrations must not enter the stub
            m = reg_re.search(code)
            if m:
                names.append(m.group(1))
            elif "qmlRegister" in code and "org.electrum" in code:
                sys.exit(f"error: unrecognized 'org.electrum' registration in {QEAPP_PATH}:\n"
                         f"    {line.strip()}\n"
                         "Update the regex in this script, or the stub will lack this type\n"
                         "and valid QML using it will fail the lint with [import] errors.")
    if len(names) < 20:  # 29 as of 2026-08; guards against the registrations moving elsewhere
        sys.exit(f"error: found only {len(names)} qmlRegisterType calls in {QEAPP_PATH}.\n"
                 "Did the registrations move? Update this script.")
    return names


def write_module_stub(imports_dir: str, type_names: list) -> None:
    module_dir = os.path.join(imports_dir, "org", "electrum")
    os.makedirs(module_dir)
    with open(os.path.join(module_dir, "qmldir"), "w", encoding="utf-8") as f:
        f.write("module org.electrum\ntypeinfo plugins.qmltypes\n")
    components = "".join(
        '    Component { name: "%s"; exports: ["org.electrum/%s 1.0"]; '
        'accessSemantics: "reference"; prototype: "QObject" }\n' % (name, name)
        for name in type_names
    )
    with open(os.path.join(module_dir, "plugins.qmltypes"), "w", encoding="utf-8") as f:
        f.write("import QtQuick.tooling 1.2\nModule {\n" + components + "}\n")


def get_qml_files() -> list:
    bfiles = subprocess.check_output(["git", "ls-files", "--", "*.qml"])
    files = bfiles.decode("utf-8").splitlines()
    if not files:  # an empty list would make the lint vacuously green
        sys.exit("error: 'git ls-files' found no .qml files.")
    return files


def get_context_property_names() -> set:
    with open(QEAPP_PATH, "r", encoding="utf-8") as f:
        return set(re.findall(r"setContextProperty\('(\w+)'", f.read()))


def get_reported_name(warning: dict, source_lines: list) -> str:
    """Returns the identifier an 'unqualified' warning is about."""
    m = re.match(r'no matching signal found for handler "(\w+)"', warning["message"])
    if m:
        return m.group(1)
    start = warning["column"] - 1
    return source_lines[warning["line"] - 1][start:start + warning["length"]]


def is_known_identifier(warning: dict, name: str, source: str, context_properties: set) -> bool:
    """Whether an 'unqualified' warning is a false positive caused by dynamic scoping.

    qmllint cannot see most of what QML's dynamic scoping makes available, so it
    reports e.g. every use of a context property. What is left after excluding
    those names is an identifier that is not declared anywhere: likely a typo.
    If this returns False for all names, the lint only gets noisier, not laxer.
    """
    suggestions = " ".join(s.get("message", "") for s in warning.get("suggestions", []))
    if "is a member of a parent element" in suggestions or "ComponentBehavior" in suggestions:
        return True  # qmllint itself resolved the name
    if name in context_properties or name in ROOT_WINDOW_NAMES or name in DELEGATE_NAMES:
        return True
    n = re.escape(name)
    declaration = rf"\b(?:function|signal)\s+{n}\b|\bid:\s*{n}\b|\bproperty\s+[\w<>.]+\s+{n}\b"
    return re.search(declaration, source) is not None


def run_qmllint(qmllint_path: str, imports_dir: str, qml_files: list) -> list:
    proc = subprocess.run([qmllint_path, "--json", "-", "-I", imports_dir] + qml_files,
                          stdout=subprocess.PIPE)
    # MaxWarnings makes qmllint exit with 255 on any warning, so that is expected here
    if proc.returncode not in (0, 255):
        sys.exit(f"error: qmllint exited with code {proc.returncode}.")
    try:
        results = json.loads(proc.stdout)["files"]
    except (ValueError, KeyError) as e:
        sys.exit(f"error: could not parse the output of qmllint: {e!r}")
    if len(results) != len(qml_files):
        sys.exit(f"error: qmllint reported on {len(results)} of {len(qml_files)} files.")
    return results


def main():
    qmllint_path = find_qmllint()
    qml_files = get_qml_files()
    type_names = get_registered_type_names()
    context_properties = get_context_property_names()
    with tempfile.TemporaryDirectory() as imports_dir:
        write_module_stub(imports_dir, type_names)
        results = run_qmllint(qmllint_path, imports_dir, qml_files)

    violations = []
    info_counts = collections.Counter()
    filtered_count = 0
    used_dynamic_scope_names = set()
    for result in results:
        path = os.path.relpath(result["filename"])
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        source_lines = source.splitlines()
        for warning in result["warnings"]:
            if warning["type"] == "info":
                info_counts[warning["id"]] += 1
                continue
            if warning["id"] == "unqualified":
                name = get_reported_name(warning, source_lines)
                if name in DYNAMIC_SCOPE_NAMES.get(path, ()):
                    used_dynamic_scope_names.add((path, name))
                    filtered_count += 1
                    continue
                if is_known_identifier(warning, name, source, context_properties):
                    filtered_count += 1
                    continue
            location = f"{path}:{warning.get('line', '?')}:{warning.get('column', '?')}"
            hints = "".join(f"\n    {s['message']}" for s in warning.get("suggestions", []))
            violations.append(f"{location}: {warning['message']} [{warning['id']}]{hints}")

    for path, names in sorted(DYNAMIC_SCOPE_NAMES.items()):
        for name in sorted(names):
            if (path, name) not in used_dynamic_scope_names:
                violations.append(f"{path}: remove '{name}' from DYNAMIC_SCOPE_NAMES in this script, "
                                  "it is no longer needed")

    for violation in violations:
        print(f"Warning: {violation}")
    print(f"qmllint: checked {len(qml_files)} files ({len(type_names)} org.electrum stub types): "
          f"{len(violations)} violations, {filtered_count} filtered dynamic scope warnings, "
          f"info-level (not gating): {dict(sorted(info_counts.items()))}")
    sys.exit(1 if violations else 0)


if __name__ == "__main__":
    main()
