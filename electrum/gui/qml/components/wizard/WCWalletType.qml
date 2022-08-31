import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

WizardComponent {
    valid: wallettypegroup.checkedButton !== null

    onAccept: {
        wizard_data['wallet_type'] = wallettypegroup.checkedButton.wallettype
    }

    ButtonGroup {
        id: wallettypegroup
    }

    GridLayout {
        columns: 1
        Label { text: qsTr('What kind of wallet do you want to create?') }
        RadioButton {
            ButtonGroup.group: wallettypegroup
            property string wallettype: 'standard'
            checked: true
            text: qsTr('Standard Wallet')
        }
        RadioButton {
            enabled: false
            ButtonGroup.group: wallettypegroup
            property string wallettype: '2fa'
            text: qsTr('Wallet with two-factor authentication')
        }
        RadioButton {
            enabled: false
            ButtonGroup.group: wallettypegroup
            property string wallettype: 'multisig'
            text: qsTr('Multi-signature wallet')
        }
        RadioButton {
            enabled: false
            ButtonGroup.group: wallettypegroup
            property string wallettype: 'import'
            text: qsTr('Import Bitcoin addresses or private keys')
        }
    }
}
