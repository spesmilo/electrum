import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

WizardComponent {
    valid: wallettypegroup.checkedButton !== null

    function apply() {
        wizard_data['wallet_type'] = wallettypegroup.checkedButton.wallettype
        if (wizard_data['wallet_type'] == 'standard')
            wizard_data['seed_type'] = 'segwit'
        else if (wizard_data['wallet_type'] == '2fa')
            wizard_data['seed_type'] = '2fa_segwit'
        // TODO: multisig
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
            ButtonGroup.group: wallettypegroup
            property string wallettype: '2fa'
            text: qsTr('Wallet with two-factor authentication')
        }
        RadioButton {
            ButtonGroup.group: wallettypegroup
            property string wallettype: 'multisig'
            text: qsTr('Multi-signature wallet')
        }
        RadioButton {
            ButtonGroup.group: wallettypegroup
            property string wallettype: 'imported'
            text: qsTr('Import Bitcoin addresses or private keys')
        }
    }
}
