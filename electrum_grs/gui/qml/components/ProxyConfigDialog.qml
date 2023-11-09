import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: rootItem

    title: qsTr('Proxy settings')

    width: parent.width
    height: parent.height

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

        if ('mode' in p) {
            proxyconfig.proxy_enabled = true
            proxyconfig.proxy_address = p['host']
            proxyconfig.proxy_port = p['port']
            proxyconfig.username = p['user']
            proxyconfig.password = p['password']
            proxyconfig.proxy_type = proxyconfig.proxy_type_map.map(function(x) {
                return x.value
            }).indexOf(p['mode'])
        } else {
            proxyconfig.proxy_enabled = false
        }
    }
}
