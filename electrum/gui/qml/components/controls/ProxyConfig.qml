import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

Item {
    id: pc

    property alias proxy_enabled: proxy_enabled_cb.checked
    property alias proxy_type: proxytype.currentIndex
    property alias proxy_address: address.text
    property alias proxy_port: port.text
    property alias username: username_tf.text
    property alias password: password_tf.text

    property var proxy_types: ['TOR', 'SOCKS5', 'SOCKS4']

    height: rootLayout.height

    function toProxyDict() {
        var p = {}
        p['enabled'] = pc.proxy_enabled
        if (pc.proxy_enabled) {
            var type = pc.proxy_types[pc.proxy_type].toLowerCase()
            if (type == 'tor')
                type = 'socks5'
            p['mode'] = type
            p['host'] = pc.proxy_address
            p['port'] = pc.proxy_port
            p['user'] = pc.username
            p['password'] = pc.password
        }
        return p
    }

    ColumnLayout {
        id: rootLayout

        width: parent.width
        spacing: constants.paddingLarge

        Label {
            text: qsTr('Proxy settings')
        }

        CheckBox {
            id: proxy_enabled_cb
            text: qsTr('Enable Proxy')
        }

        ComboBox {
            id: proxytype
            enabled: proxy_enabled_cb.checked
            model: proxy_types
            onCurrentIndexChanged: {
                if (currentIndex == 0) {
                    address.text = "127.0.0.1"
                    port.text = "9050"
                }
            }
        }

        GridLayout {
            columns: 4
            Layout.fillWidth: true

            Label {
                text: qsTr("Address")
                enabled: address.enabled
            }

            TextField {
                id: address
                enabled: proxytype.enabled && proxytype.currentIndex > 0
            }

            Label {
                text: qsTr("Port")
                enabled: port.enabled
            }

            TextField {
                id: port
                enabled: proxytype.enabled && proxytype.currentIndex > 0
            }

            Label {
                text: qsTr("Username")
                enabled: username_tf.enabled
            }

            TextField {
                id: username_tf
                enabled: proxytype.enabled && proxytype.currentIndex > 0
            }

            Label {
                text: qsTr("Password")
                enabled: password_tf.enabled
            }

            PasswordField {
                id: password_tf
                enabled: proxytype.enabled && proxytype.currentIndex > 0
            }
        }
    }
}
