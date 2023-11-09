import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "wizard"

Wizard {
    id: walletwizard

    wizardTitle: qsTr('New Wallet')

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
            var dialog = app.messageDialog.createObject(app, { text: error })
            dialog.open()
        }
    }
}

