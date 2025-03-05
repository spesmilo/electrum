import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

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

    property bool _probing: false

    function toProxyDict() {
        var p = {}
        p['enabled'] = pc.proxy_enabled
        var type = proxy_type_map[pc.proxy_type]['value']
        p['mode'] = type
        p['host'] = pc.proxy_address
        p['port'] = pc.proxy_port
        p['user'] = pc.username
        p['password'] = pc.password
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
                inputMethodHints: Qt.ImhNoPredictiveText
            }

            Label {
                text: qsTr("Port")
                enabled: port.enabled
            }

            TextField {
                id: port
                enabled: proxy_enabled_cb.checked
                inputMethodHints: Qt.ImhDigitsOnly
            }

            Label {
                text: qsTr("Username")
                enabled: username_tf.enabled
            }

            TextField {
                id: username_tf
                enabled: proxy_enabled_cb.checked
                inputMethodHints: Qt.ImhNoPredictiveText
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

        Pane {
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: constants.paddingLarge
            padding: 0
            background: Rectangle {
                color: constants.darkerDialogBackground
            }
            FlatButton {
                enabled: proxy_enabled_cb.checked && !_probing
                text: qsTr('Detect Tor proxy')
                onClicked: {
                    _probing = true
                    Network.probeTor()
                }
            }
        }

        BusyIndicator {
            id: spinner
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: constants.paddingSmall
            Layout.preferredWidth: constants.iconSizeXLarge
            Layout.preferredHeight: constants.iconSizeXLarge
            running: visible
            visible: _probing
        }
    }

    Connections {
        target: Network
        function onTorProbeFinished(host, port) {
            _probing = false
            if (host && port) {
                proxytype.currentIndex = 0
                proxy_port = ""+port
                proxy_address = host
            }
        }
    }
}
