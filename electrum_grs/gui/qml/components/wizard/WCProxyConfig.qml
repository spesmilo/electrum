import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

WizardComponent {
    valid: true

    onAccept: {
        var p = {}
        p['enabled'] = proxy_enabled.checked
        if (proxy_enabled.checked) {
            var type = proxytype.currentValue.toLowerCase()
            if (type == 'tor')
                type = 'socks5'
            p['mode'] = type
            p['host'] = address.text
            p['port'] = port.text
            p['user'] = username.text
            p['password'] = password.text
        }
        wizard_data['proxy'] = p
    }

    ColumnLayout {
        width: parent.width

        Label {
            text: qsTr('Proxy settings')
        }

        CheckBox {
            id: proxy_enabled
            text: qsTr('Enable Proxy')
        }

        ComboBox {
            id: proxytype
            enabled: proxy_enabled.checked
            model: ['TOR', 'SOCKS5', 'SOCKS4']
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
                enabled: username.enabled
            }

            TextField {
                id: username
                enabled: proxytype.enabled && proxytype.currentIndex > 0
            }

            Label {
                text: qsTr("Password")
                enabled: password.enabled
            }

            TextField {
                id: password
                enabled: proxytype.enabled && proxytype.currentIndex > 0
                echoMode: TextInput.Password
            }
        }
    }

}
