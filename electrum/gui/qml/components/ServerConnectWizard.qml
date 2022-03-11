import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3

import "wizard"

Wizard {
    id: serverconnectwizard

    title: qsTr('How do you want to connect to a server?')

    enter: null // disable transition

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
        var start = _loadNextComponent(autoconnect)
        start.next.connect(function() {autoconnectDone()})
    }

    function autoconnectDone() {
        var page = _loadNextComponent(proxyconfig, wizard_data)
        page.next.connect(function() {proxyconfigDone()})
    }

    function proxyconfigDone() {
        var page = _loadNextComponent(serverconfig, wizard_data)
    }

    property Component autoconnect: Component {
        WCAutoConnect {}
    }

    property Component proxyconfig: Component {
        WCProxyConfig {}
    }

    property Component serverconfig: Component {
        WCServerConfig {}
    }

}
