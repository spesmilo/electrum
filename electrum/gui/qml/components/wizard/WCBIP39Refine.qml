import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import ".."

WizardComponent {
    valid: false

    onAccept: {
    }

    function setDerivationPath() {
        var addrtype = {
            'p2pkh': 44,
            'p2wpkh-p2sh': 49,
            'p2wpkh': 84
        }
        var nChain = Network.isTestNet ? 1 : 0
        derivationpathtext.text =
            "m/" + addrtype[addresstypegroup.checkedButton.addresstype] + "'/"
            + (Network.isTestNet ? 1 : 0) + "'/0'"
    }

    ButtonGroup {
        id: addresstypegroup
        onCheckedButtonChanged: {
            console.log('button changed: ' + checkedButton.addresstype)
            setDerivationPath()
        }
    }

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height
        clip:true
        interactive: height < contentHeight

        GridLayout {
            id: mainLayout
            width: parent.width
            columns: 1

            Label { text: qsTr('Script type and Derivation path') }
            Button {
                text: qsTr('Detect Existing Accounts')
                enabled: false
            }
            Label { text: qsTr('Choose the type of addresses in your wallet.') }
            RadioButton {
                ButtonGroup.group: addresstypegroup
                property string addresstype: 'p2pkh'
                text: qsTr('legacy (p2pkh)')
            }
            RadioButton {
                ButtonGroup.group: addresstypegroup
                property string addresstype: 'p2wpkh-p2sh'
                text: qsTr('wrapped segwit (p2wpkh-p2sh)')
            }
            RadioButton {
                ButtonGroup.group: addresstypegroup
                property string addresstype: 'p2wpkh'
                checked: true
                text: qsTr('native segwit (p2wpkh)')
            }
            InfoTextArea {
                text: qsTr('You can override the suggested derivation path.') + ' ' +
                    qsTr('If you are not sure what this is, leave this field unchanged.')
            }
            TextField {
                id: derivationpathtext
                Layout.fillWidth: true
                placeholderText: qsTr('Derivation path')
            }
        }
    }
}

