import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "wizard"

// Material 3 network wizard of the first start (app.serverConnectWizard).
// repeats: components/ServerConnectWizard.qml:7-30 @ e6df7e1c8 (verbatim; the base is the Material 3 Wizard).
// M3: no close button on the first page: cancelling this wizard quits the app (main.qml), the Android back key
// is the way out, as in the classic (DESIGN-M2.md finding 6).
Wizard {
    id: serverconnectwizard

    wizardTitle: qsTranslate('ServerConnectWizard', 'Network configuration')
    canCancel: false

    enter: null // disable transition

    wiz: Daemon.serverConnectWizard
    finishButtonText: qsTranslate('ServerConnectWizard', 'Next')

    onAccepted: {
        var proxy = wizard_data['proxy']
        if (proxy && proxy['enabled'] == true) {
            Network.proxy = proxy
        } else {
            Network.proxy = {'enabled': false}
        }
        Network.setServerParameters(wizard_data['server'], wizard_data['autoconnect'], wizard_data['one_server'])
    }

    Component.onCompleted: {
        var view = wiz.startWizard()
        _loadNextComponent(view)
    }
}
