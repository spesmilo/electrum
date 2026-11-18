import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "wizard"

// Material 3 wizard for a new wallet (app.newWalletWizard).
// repeats: components/NewWalletWizard.qml:9-45 @ e6df7e1c8 (verbatim; the base is the Material 3 Wizard).
Wizard {
    id: walletwizard

    wizardTitle: qsTranslate('NewWalletWizard', 'New Wallet')

    signal walletCreated

    property string path

    wiz: Daemon.newWalletWizard

    Component.onCompleted: {
        var view = wiz.startWizard()
        _loadNextComponent(view)
    }

    onAccepted: {
        console.log('Finished new wallet wizard')
        wiz.createStorage(wizard_data, Daemon.singlePasswordEnabled, Daemon.singlePassword)
    }

    Connections {
        target: wiz
        function onCreateSuccess() {
            walletwizard.path = wiz.path
            walletwizard.walletCreated()
        }
        function onCreateError(error) {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTranslate('NewWalletWizard', 'Error'),
                iconSource: Qt.resolvedUrl('../../icons/m3/warning.png'),
                text: error
            })
            dialog.open()
        }
    }
}
