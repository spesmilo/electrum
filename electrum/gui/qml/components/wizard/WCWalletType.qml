import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

WizardComponent {
    valid: wallettypegroup.checkedButton !== null

    function apply() {
        // apply gets called when the page is rendered and implicitly
        // sets the first radio button or the last selected one when going back
        wizard_data['wallet_type'] = wallettypegroup.checkedButton.wallettype
        delete wizard_data['seed_type']
        if (wizard_data['wallet_type'] == 'standard')
            wizard_data['seed_type'] = 'segwit'
        else if (wizard_data['wallet_type'] == '2fa')
            wizard_data['seed_type'] = '2fa_segwit'
        else if (wizard_data['wallet_type'] == 'multisig')
            wizard_data['seed_type'] = 'segwit'
    }

    ButtonGroup {
        id: wallettypegroup
    }

    ColumnLayout {
        width: parent.width

        Label {
            Layout.fillWidth: true
            text: qsTr('What kind of wallet do you want to create?')
            wrapMode: Text.Wrap
        }
        ElRadioButton {
            Layout.fillWidth: true
            ButtonGroup.group: wallettypegroup
            property string wallettype: 'standard'
            checked: true
            text: qsTr('Standard Wallet')
        }
        ElRadioButton {
            Layout.fillWidth: true
            ButtonGroup.group: wallettypegroup
            property string wallettype: '2fa'
            text: qsTr('Wallet with two-factor authentication')
        }
        ElRadioButton {
            Layout.fillWidth: true
            ButtonGroup.group: wallettypegroup
            property string wallettype: 'multisig'
            text: qsTr('Multi-signature wallet')
        }
        ElRadioButton {
            Layout.fillWidth: true
            ButtonGroup.group: wallettypegroup
            property string wallettype: 'imported'
            text: qsTr('Import Bitcoin addresses or private keys')
        }
    }
}
