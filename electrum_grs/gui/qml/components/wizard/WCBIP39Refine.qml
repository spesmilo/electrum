import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

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
        var p = isMultisig ? getMultisigScriptTypePurposeDict() : getScriptTypePurposeDict()
        if (!scripttypegroup.checkedButton.scripttype in p)
            return
        if (!bitcoin.verifyDerivationPath(derivationpathtext.text))
            return
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
                text: qsTr('Script type and Derivation path')
            }
            Button {
                text: qsTr('Detect Existing Accounts')
                enabled: false
                visible: !isMultisig
            }

            Label {
                text: qsTr('Choose the type of addresses in your wallet.')
            }

            // standard
            RadioButton {
                ButtonGroup.group: scripttypegroup
                property string scripttype: 'p2pkh'
                text: qsTr('legacy (p2pkh)')
                visible: !isMultisig
            }
            RadioButton {
                ButtonGroup.group: scripttypegroup
                property string scripttype: 'p2wpkh-p2sh'
                text: qsTr('wrapped segwit (p2wpkh-p2sh)')
                visible: !isMultisig
            }
            RadioButton {
                ButtonGroup.group: scripttypegroup
                property string scripttype: 'p2wpkh'
                checked: !isMultisig
                text: qsTr('native segwit (p2wpkh)')
                visible: !isMultisig
            }

            // multisig
            RadioButton {
                ButtonGroup.group: scripttypegroup
                property string scripttype: 'p2sh'
                text: qsTr('legacy multisig (p2sh)')
                visible: isMultisig
            }
            RadioButton {
                ButtonGroup.group: scripttypegroup
                property string scripttype: 'p2wsh-p2sh'
                text: qsTr('p2sh-segwit multisig (p2wsh-p2sh)')
                visible: isMultisig
            }
            RadioButton {
                ButtonGroup.group: scripttypegroup
                property string scripttype: 'p2wsh'
                checked: isMultisig
                text: qsTr('native segwit multisig (p2wsh)')
                visible: isMultisig
            }

            InfoTextArea {
                Layout.preferredWidth: parent.width
                text: qsTr('You can override the suggested derivation path.') + ' ' +
                    qsTr('If you are not sure what this is, leave this field unchanged.')
            }

            TextField {
                id: derivationpathtext
                Layout.fillWidth: true
                placeholderText: qsTr('Derivation path')
                onTextChanged: validate()
            }
        }
    }

    Bitcoin {
        id: bitcoin
    }

    Component.onCompleted: {
        isMultisig = wizard_data['wallet_type'] == 'multisig'
        if (isMultisig) {
            participants = wizard_data['multisig_participants']
            if ('multisig_current_cosigner' in wizard_data)
                cosigner = wizard_data['multisig_current_cosigner']
        }
    }
}

