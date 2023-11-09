import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

WizardComponent {
    valid: wallet_name.text.length > 0 && !Daemon.availableWallets.wallet_name_exists(wallet_name.text)

    function apply() {
        wizard_data['wallet_name'] = wallet_name.text
    }

    GridLayout {
        columns: 1
        Label { text: qsTr('Wallet name') }
        TextField {
            id: wallet_name
            focus: true
            text: Daemon.suggestWalletName()
        }
    }

    Component.onCompleted: {
        wallet_name.forceActiveFocus()
    }
}
