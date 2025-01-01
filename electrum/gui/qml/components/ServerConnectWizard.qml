import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "wizard"

Wizard {
    id: serverconnectwizard

    wizardTitle: qsTr('Network configuration')

    enter: null // disable transition

    wiz: Daemon.serverConnectWizard
    finishButtonText: qsTr('Next')

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
        var view = wiz.startWizard()
        _loadNextComponent(view)
    }
}
