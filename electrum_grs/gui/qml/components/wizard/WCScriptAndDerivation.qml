import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import ".."
import "../controls"

WizardComponent {
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
        if (!bitcoin.verifyDerivationPath(derivationpathtext.text))
            return

        if (isMultisig && cosigner) {
            apply()
            if (wiz.hasDuplicateMasterKeys(wizard_data)) {
                validationtext.text = qsTr('Error: duplicate master public key')
                return
            } else if (wiz.hasHeterogeneousMasterKeys(wizard_data)) {
                validationtext.text = qsTr('Error: master public key types do not match')
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
        anchors.fill: parent
        contentHeight: mainLayout.height
        clip:true
        interactive: height < contentHeight

        ColumnLayout {
            id: mainLayout
            width: parent.width

            Label {
                Layout.fillWidth: true
                text: qsTr('Choose the type of addresses in your wallet.')
                wrapMode: Text.Wrap
            }

            // standard
            ElRadioButton {
                Layout.fillWidth: true
                ButtonGroup.group: scripttypegroup
                property string scripttype: 'p2pkh'
                text: qsTr('legacy (p2pkh)')
                visible: !isMultisig
            }
            ElRadioButton {
                Layout.fillWidth: true
                ButtonGroup.group: scripttypegroup
                property string scripttype: 'p2wpkh-p2sh'
                text: qsTr('wrapped segwit (p2wpkh-p2sh)')
                visible: !isMultisig
            }
            ElRadioButton {
                Layout.fillWidth: true
                ButtonGroup.group: scripttypegroup
                property string scripttype: 'p2wpkh'
                checked: !isMultisig
                text: qsTr('native segwit (p2wpkh)')
                visible: !isMultisig
            }

            // multisig
            ElRadioButton {
                Layout.fillWidth: true
                ButtonGroup.group: scripttypegroup
                property string scripttype: 'p2sh'
                text: qsTr('legacy multisig (p2sh)')
                visible: isMultisig
                enabled: !cosigner || wizard_data['script_type'] == 'p2sh'
                checked: cosigner ? wizard_data['script_type'] == 'p2sh' : false
            }
            ElRadioButton {
                Layout.fillWidth: true
                ButtonGroup.group: scripttypegroup
                property string scripttype: 'p2wsh-p2sh'
                text: qsTr('p2sh-segwit multisig (p2wsh-p2sh)')
                visible: isMultisig
                enabled: !cosigner || wizard_data['script_type'] == 'p2wsh-p2sh'
                checked: cosigner ? wizard_data['script_type'] == 'p2wsh-p2sh' : false
            }
            ElRadioButton {
                Layout.fillWidth: true
                ButtonGroup.group: scripttypegroup
                property string scripttype: 'p2wsh'
                text: qsTr('native segwit multisig (p2wsh)')
                visible: isMultisig
                enabled: !cosigner || wizard_data['script_type'] == 'p2wsh'
                checked: cosigner ? wizard_data['script_type'] == 'p2wsh' : isMultisig
            }

            InfoTextArea {
                Layout.fillWidth: true
                text: qsTr('You can override the suggested derivation path.') + ' ' +
                    qsTr('If you are not sure what this is, leave this field unchanged.')
            }

            Label {
                text: qsTr('Derivation path')
            }

            TextField {
                id: derivationpathtext
                Layout.fillWidth: true
                Layout.leftMargin: constants.paddingMedium
                onTextChanged: validate()
            }

            InfoTextArea {
                id: validationtext
                Layout.fillWidth: true
                visible: text
                iconStyle: InfoTextArea.IconStyle.Error
            }

            Pane {
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: constants.paddingLarge
                padding: 0
                visible: !isMultisig
                background: Rectangle {
                    color: Qt.lighter(Material.dialogColor, 1.5)
                }

                FlatButton {
                    text: qsTr('Detect Existing Accounts')
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
            }

        }
    }

    Bitcoin {
        id: bitcoin
    }

    Component {
        id: bip39recoveryDialog
        BIP39RecoveryDialog { }
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

