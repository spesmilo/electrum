import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3

import "wizard"

Wizard {
    id: serverconnectwizard

    wizardTitle: qsTr('Network configuration')

    enter: null // disable transition

    wiz: Daemon.serverConnectWizard

    onAccepted: {
        var proxy = wizard_data['proxy']
        if (proxy && proxy['enabled'] == true) {
            Network.proxy = proxy
        } else {
            Network.proxy = {'enabled': false}
        }
        Config.autoConnect = wizard_data['autoconnect']
        if (!wizard_data['autoconnect']) {
            Network.server = wizard_data['server']
        }
    }

    Component.onCompleted: {
        var view = wiz.start_wizard()
        _loadNextComponent(view)
    }
}
