import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

WizardComponent {
    valid: wiz.isValidNewWalletName(wallet_name.text)

    function apply() {
        wizard_data['wallet_name'] = wallet_name.text
    }

    ColumnLayout {
        width: parent.width

        Label {
            text: qsTr('Wallet name')
        }

        TextField {
            id: wallet_name
            Layout.fillWidth: true
            focus: true
            text: Daemon.suggestWalletName()
            inputMethodHints: Qt.ImhNoPredictiveText
        }
    }

    Component.onCompleted: {
        wallet_name.forceActiveFocus()
    }
}
