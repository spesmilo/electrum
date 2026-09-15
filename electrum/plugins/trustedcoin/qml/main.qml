import QtQuick

import org.electrum

Item {
    Connections {
        target: AppController ? AppController.plugin('trustedcoin') : null
        function onCosignerWalletCreated() {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Two-factor authentication'),
                text: qsTr('This device is now a cosigner of your desktop wallet.')
            })
            dialog.open()
        }
    }
}
