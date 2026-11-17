import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import ".."
import "../controls"

// Material 3 page: the type of addresses and the derivation path (restore from a BIP39 seed, multisig).
// repeats: components/wizard/WCScriptAndDerivation.qml:11-236 @ e6df7e1c8 (valid, isMultisig, cosigner,
// participants; apply() for the wallet or the cosigner; the purpose tables; validate() with
// bitcoin.verifyDerivationPath and the duplicate / heterogeneous master key checks of a cosigner;
// setDerivationPath(); the ButtonGroup and setDerivationPath() on every change of the option; the six options with
// their `scripttype` and the expressions of visible / enabled / checked; the derivation path field validated on
// every change; "Detect Existing Accounts" with BIP39RecoveryDialog (Material 3, components_m3/, by `import ".."`)
// and the handling of its accepted(); Component.onCompleted reading wizard_data).
// Look (DESIGN-M2-onboarding.md 3.1): the question as the heading, the options as M3RadioRow in an M3ListGroup,
// the notice and the error as M3InfoText, the path as M3TextField, the button as a tonal M3Button.
// M3: "Detect Existing Accounts" stands above the list of options (PERSONA-CRITIQUE-M2-onboarding finding 21: the
// one step a newcomer understands, otherwise below six lines of script types); same action, same condition.
// Strings carried over keep the translation context of WCScriptAndDerivation.qml.
WizardComponent {
    id: root
    valid: false

    property bool isMultisig: false
    property int cosigner: 0
    property int participants: 0

    function apply() {
        if (cosigner) {
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['script_type'] = scripttypegroup.checkedButton.scripttype
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['derivation_path'] = derivationpathtext.text
        } else {
            wizard_data['script_type'] = scripttypegroup.checkedButton.scripttype
            wizard_data['derivation_path'] = derivationpathtext.text
        }
    }

    function getScriptTypePurposeDict() {
        return {
            'p2pkh': 44,
            'p2wpkh-p2sh': 49,
            'p2wpkh': 84
        }
    }

    function getMultisigScriptTypePurposeDict() {
        return {
            'p2sh': 45,
            'p2wsh-p2sh': 48,
            'p2wsh': 48
        }
    }

    function validate() {
        valid = false
        validationtext.text = ''

        var p = isMultisig ? getMultisigScriptTypePurposeDict() : getScriptTypePurposeDict()
        if (!scripttypegroup.checkedButton.scripttype in p)
            return
        if (!bitcoin.verifyDerivationPath(derivationpathtext.text)) {
            validationtext.text = qsTranslate('WCScriptAndDerivation', 'Invalid derivation path')
            return
        }

        if (isMultisig && cosigner) {
            apply()
            if (wiz.hasDuplicateMasterKeys(wizard_data)) {
                validationtext.text = qsTranslate('WCScriptAndDerivation', 'Error: duplicate master public key')
                return
            } else if (wiz.hasHeterogeneousMasterKeys(wizard_data)) {
                validationtext.text = qsTranslate('WCScriptAndDerivation', 'Error: master public key types do not match')
                return
            }
        }
        valid = true
    }

    function setDerivationPath() {
        var p = isMultisig ? getMultisigScriptTypePurposeDict() : getScriptTypePurposeDict()
        var scripttype = scripttypegroup.checkedButton.scripttype
        if (isMultisig) {
            if (scripttype == 'p2sh')
                derivationpathtext.text = "m/" + p[scripttype] + "'/0"
            else
                derivationpathtext.text = "m/" + p[scripttype] + "'/"
                + (Network.isTestNet ? 1 : 0) + "'/0'/"
                + (scripttype == 'p2wsh' ? 2 : 1) + "'"
        } else {
            derivationpathtext.text =
                "m/" + p[scripttypegroup.checkedButton.scripttype] + "'/"
                + (Network.isTestNet ? 1 : 0) + "'/0'"
        }
    }

    ButtonGroup {
        id: scripttypegroup
        onCheckedButtonChanged: {
            setDerivationPath()
        }
    }

    Flickable {
        id: flick
        anchors.fill: parent
        contentHeight: mainLayout.height + m3.space16
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        onHeightChanged: {
            if (derivationpathtext.activeFocus)
                root.ensureVisible(flick, derivationpathField)
        }

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: m3.space16

            M3Text {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                role: 'titleMedium'
                wrapMode: Text.Wrap
                text: qsTranslate('WCScriptAndDerivation', 'Choose the type of addresses in your wallet.')
            }

            M3Button {
                visible: !isMultisig
                variant: 'tonal'
                text: qsTranslate('WCScriptAndDerivation', 'Detect Existing Accounts')
                onClicked: {
                    var dialog = bip39recoveryDialog.createObject(mainLayout, {
                        walletType: wizard_data['wallet_type'],
                        seed: wizard_data['seed'],
                        seedExtraWords: wizard_data['seed_extra_words']
                    })
                    dialog.accepted.connect(function () {
                        // select matching script type button and set derivation path
                        for (var i = 0; i < scripttypegroup.buttons.length; i++) {
                            var btn = scripttypegroup.buttons[i]
                            if (btn.visible && btn.scripttype == dialog.scriptType) {
                                btn.checked = true
                                derivationpathtext.text = dialog.derivationPath
                                return
                            }
                        }
                    })
                    dialog.open()
                }
            }

            M3ListGroup {
                Layout.fillWidth: true

                // standard
                M3RadioRow {
                    ButtonGroup.group: scripttypegroup
                    property string scripttype: 'p2pkh'
                    text: qsTranslate('WCScriptAndDerivation', 'legacy (p2pkh)')
                    visible: !isMultisig
                }
                M3RadioRow {
                    ButtonGroup.group: scripttypegroup
                    property string scripttype: 'p2wpkh-p2sh'
                    text: qsTranslate('WCScriptAndDerivation', 'wrapped segwit (p2wpkh-p2sh)')
                    visible: !isMultisig
                }
                M3RadioRow {
                    ButtonGroup.group: scripttypegroup
                    property string scripttype: 'p2wpkh'
                    checked: !isMultisig
                    text: qsTranslate('WCScriptAndDerivation', 'native segwit (p2wpkh)')
                    visible: !isMultisig
                }

                // multisig
                M3RadioRow {
                    ButtonGroup.group: scripttypegroup
                    property string scripttype: 'p2sh'
                    text: qsTranslate('WCScriptAndDerivation', 'legacy multisig (p2sh)')
                    visible: isMultisig
                    enabled: !cosigner || wizard_data['script_type'] == 'p2sh'
                    checked: cosigner ? wizard_data['script_type'] == 'p2sh' : false
                }
                M3RadioRow {
                    ButtonGroup.group: scripttypegroup
                    property string scripttype: 'p2wsh-p2sh'
                    text: qsTranslate('WCScriptAndDerivation', 'p2sh-segwit multisig (p2wsh-p2sh)')
                    visible: isMultisig
                    enabled: !cosigner || wizard_data['script_type'] == 'p2wsh-p2sh'
                    checked: cosigner ? wizard_data['script_type'] == 'p2wsh-p2sh' : false
                }
                M3RadioRow {
                    ButtonGroup.group: scripttypegroup
                    property string scripttype: 'p2wsh'
                    text: qsTranslate('WCScriptAndDerivation', 'native segwit multisig (p2wsh)')
                    visible: isMultisig
                    enabled: !cosigner || wizard_data['script_type'] == 'p2wsh'
                    checked: cosigner ? wizard_data['script_type'] == 'p2wsh' : isMultisig
                }
            }

            M3InfoText {
                Layout.fillWidth: true
                compact: true
                text: qsTranslate('WCScriptAndDerivation', 'You can override the suggested derivation path.') + ' ' +
                    qsTranslate('WCScriptAndDerivation', 'If you are not sure what this is, leave this field unchanged.')
            }

            M3TextField {
                id: derivationpathField
                Layout.fillWidth: true
                inputMethodHints: Qt.ImhNoPredictiveText
                label: qsTranslate('WCScriptAndDerivation', 'Derivation path')

                onTextChanged: validate()
            }

            M3InfoText {
                id: validationtext
                Layout.fillWidth: true
                compact: true
                visible: text
                iconStyle: M3InfoText.IconStyle.Error
            }
        }
    }

    // the TextField of the classic page
    property alias derivationpathtext: derivationpathField.field

    Connections {
        target: derivationpathField.field
        function onActiveFocusChanged() {
            if (derivationpathField.field.activeFocus)
                Qt.callLater(root.ensureVisible, flick, derivationpathField)
        }
    }

    Bitcoin {
        id: bitcoin
    }

    Component {
        id: bip39recoveryDialog
        BIP39RecoveryDialog {
            onClosed: destroy()
        }
    }

    Component.onCompleted: {
        isMultisig = wizard_data['wallet_type'] == 'multisig'
        if (isMultisig) {
            participants = wizard_data['multisig_participants']
            if ('multisig_current_cosigner' in wizard_data)
                cosigner = wizard_data['multisig_current_cosigner']
            validate()
        }
    }
}
