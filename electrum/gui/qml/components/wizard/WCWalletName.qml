import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../controls"

WizardComponent {
    valid: Daemon.isValidWalletName(wallet_name.text)

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

        // this device can be set up as cosigner of another wallet, without having one
        FlatButton {
            Layout.fillWidth: true
            Layout.topMargin: constants.paddingLarge
            text: qsTr('Scan QR code')
            icon.source: Qt.resolvedUrl('../../../icons/qrcode.png')
            visible: !Cosigner.hasWallets()
            onClicked: app.cosignerHandler.scanQrCode()
        }
    }

    Component.onCompleted: {
        wallet_name.forceActiveFocus()
    }
}
