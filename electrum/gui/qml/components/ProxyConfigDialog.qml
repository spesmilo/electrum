import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: rootItem

    title: qsTr('Proxy settings')

    parent: Overlay.overlay
    modal: true
    standardButtons: Dialog.Close

    width: parent.width
    height: parent.height

    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    padding: 0

    ColumnLayout {
        width: parent.width
        height: parent.height
        spacing: 0

        ProxyConfig {
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge
            id: proxyconfig
        }

        Item { Layout.fillHeight: true; Layout.preferredWidth: 1 }

        FlatButton {
            Layout.fillWidth: true
            text: qsTr('Ok')
            icon.source: '../../icons/confirmed.png'
            onClicked: {
                var proxy = proxyconfig.toProxyDict()
                if (proxy && proxy['enabled'] == true) {
                    Network.proxy = proxy
                } else {
                    Network.proxy = {'enabled': false}
                }
                rootItem.close()
            }
        }
    }


    Component.onCompleted: {
        var p = Network.proxy
        console.log(JSON.stringify(p))

        if ('mode' in p) {
            proxyconfig.proxy_enabled = true
            proxyconfig.proxy_address = p['host']
            proxyconfig.proxy_port = p['port']
            proxyconfig.username = p['user']
            proxyconfig.password = p['password']
            if (p['mode'] == 'socks5' && p['port'] == 9050)
                p['mode'] = 'tor'
            proxyconfig.proxy_type = proxyconfig.proxy_types.indexOf(p['mode'].toUpperCase())
            console.log('proxy type: ' + proxyconfig.proxy_type)
        } else {
            proxyconfig.proxy_enabled = false
        }
    }
}
