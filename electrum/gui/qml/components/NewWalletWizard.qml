import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import "wizard"

Wizard {
    id: walletwizard

    wizardTitle: qsTr('New Wallet')

    signal walletCreated

    property string path

    wiz: Daemon.newWalletWizard

    Component.onCompleted: {
        var view = wiz.start_wizard()
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
    }
}

