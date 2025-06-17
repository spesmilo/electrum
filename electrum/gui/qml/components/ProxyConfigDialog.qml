import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: rootItem

    title: qsTr('Proxy settings')
    iconSource: Qt.resolvedUrl('../../icons/status_connected_proxy.png')

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
                Network.proxy = proxyconfig.toProxyDict()
                rootItem.close()
            }
        }
    }


    Component.onCompleted: {
        var p = Network.proxy

        proxyconfig.proxy_enabled = p['enabled']
        proxyconfig.proxy_address = p['host']
        proxyconfig.proxy_port = p['port']
        proxyconfig.username = p['user']
        proxyconfig.password = p['password']
        proxyconfig.proxy_type = proxyconfig.proxy_type_map.map(function(x) {
            return x.value
        }).indexOf(p['mode'])
    }
}
