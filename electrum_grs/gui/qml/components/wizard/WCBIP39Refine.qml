import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import ".."
import "../controls"

WizardComponent {
    valid: false

    function apply() {
        wizard_data['script_type'] = scripttypegroup.checkedButton.scripttype
        wizard_data['derivation_path'] = derivationpathtext.text
    }

    function getScriptTypePurposeDict() {
        return {
            'p2pkh': 44,
            'p2wpkh-p2sh': 49,
            'p2wpkh': 84
        }
    }

    function validate() {
        valid = false
        if (!scripttypegroup.checkedButton.scripttype in getScriptTypePurposeDict())
            return
        if (!bitcoin.verify_derivation_path(derivationpathtext.text))
            return
        valid = true
    }

    function setDerivationPath() {
        var p = getScriptTypePurposeDict()
        derivationpathtext.text =
            "m/" + p[scripttypegroup.checkedButton.scripttype] + "'/"
            + (Network.isTestNet ? 1 : 0) + "'/0'"
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

            Label { text: qsTr('Script type and Derivation path') }
            Button {
                text: qsTr('Detect Existing Accounts')
                enabled: false
            }
            Label { text: qsTr('Choose the type of addresses in your wallet.') }
            RadioButton {
                ButtonGroup.group: scripttypegroup
                property string scripttype: 'p2pkh'
                text: qsTr('legacy (p2pkh)')
            }
            RadioButton {
                ButtonGroup.group: scripttypegroup
                property string scripttype: 'p2wpkh-p2sh'
                text: qsTr('wrapped segwit (p2wpkh-p2sh)')
            }
            RadioButton {
                ButtonGroup.group: scripttypegroup
                property string scripttype: 'p2wpkh'
                checked: true
                text: qsTr('native segwit (p2wpkh)')
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

}

