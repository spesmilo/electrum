import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

Item {
    id: pc

    implicitHeight: rootLayout.height

    property alias proxy_enabled: proxy_enabled_cb.checked
    property alias proxy_type: proxytype.currentIndex
    property alias proxy_address: address.text
    property alias proxy_port: port.text
    property alias username: username_tf.text
    property alias password: password_tf.text

    property var proxy_type_map:  [
        { text: qsTr('SOCKS5/TOR'), value: 'socks5' },
        { text: qsTr('SOCKS4'), value: 'socks4' }
    ]

    function toProxyDict() {
        var p = {}
        p['enabled'] = pc.proxy_enabled
        if (pc.proxy_enabled) {
            var type = proxy_type_map[pc.proxy_type]['value']
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

        CheckBox {
            id: proxy_enabled_cb
            text: qsTr('Enable Proxy')
        }

        ElComboBox {
            id: proxytype
            enabled: proxy_enabled_cb.checked

            textRole: 'text'
            valueRole: 'value'
            model: proxy_type_map

            onCurrentIndexChanged: {
                if (currentIndex == 0) {
                    if (address.text == '' || port.text == '') {
                        address.text = "127.0.0.1"
                        port.text = "9050"
                    }
                }
            }
        }

        GridLayout {
            columns: 2
            Layout.fillWidth: true

            Label {
                text: qsTr("Address")
                enabled: address.enabled
            }

            TextField {
                id: address
                enabled: proxy_enabled_cb.checked
            }

            Label {
                text: qsTr("Port")
                enabled: port.enabled
            }

            TextField {
                id: port
                enabled: proxy_enabled_cb.checked
            }

            Label {
                text: qsTr("Username")
                enabled: username_tf.enabled
            }

            TextField {
                id: username_tf
                enabled: proxy_enabled_cb.checked
            }

            Label {
                text: qsTr("Password")
                enabled: password_tf.enabled
            }

            PasswordField {
                id: password_tf
                enabled: proxy_enabled_cb.checked
            }
        }
    }
}
