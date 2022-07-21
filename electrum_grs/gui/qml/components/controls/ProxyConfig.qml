import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

Item {
    property alias proxy_enabled: proxy_enabled_cb.checked
    property alias proxy_type: proxytype.currentIndex
    property alias proxy_address: address.text
    property alias proxy_port: port.text
    property alias username: username_tf.text
    property alias password: password_tf.text

    property var proxy_types: ['TOR', 'SOCKS5', 'SOCKS4']

    ColumnLayout {
        width: parent.width

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

            TextField {
                id: password_tf
                enabled: proxytype.enabled && proxytype.currentIndex > 0
                echoMode: TextInput.Password
            }
        }
    }
}
