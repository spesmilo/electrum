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
    property alias doh_endpoint: doh_endpoint_tf.text

    property bool valid: proxy_enabled
        ? address.acceptableInput && port.acceptableInput && doh_endpoint_tf.valid
        : true

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
        p['doh_endpoint'] = pc.doh_endpoint
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

        ColumnLayout {
            Layout.fillWidth: true
            spacing: constants.paddingSmall

            RowLayout {
                Layout.fillWidth: true
                Layout.rightMargin: constants.paddingLarge

                TextField {
                    id: address
                    Layout.fillWidth: true
                    enabled: proxy_enabled_cb.checked
                    inputMethodHints: Qt.ImhNoPredictiveText
                    placeholderText: qsTr("Address")
                }

                TextField {
                    id: port
                    Layout.fillWidth: true
                    enabled: proxy_enabled_cb.checked
                    inputMethodHints: Qt.ImhDigitsOnly
                    placeholderText: qsTr("Port")
                    validator: IntValidator { bottom: 1; top: 65535 }
                    color: enabled
                        ? acceptableInput ? Material.foreground : constants.colorError
                        : Material.hintTextColor
                }
            }

            Label {
                Layout.topMargin: constants.paddingLarge
                text: qsTr("Authentication")
                enabled: username_tf.enabled
            }

            TextField {
                id: username_tf
                Layout.fillWidth: true
                Layout.rightMargin: constants.paddingLarge
                enabled: proxy_enabled_cb.checked
                inputMethodHints: Qt.ImhNoPredictiveText
                placeholderText: qsTr("Username")
            }

            PasswordField {
                id: password_tf
                enabled: proxy_enabled_cb.checked
                placeholderText: qsTr("Password")
            }

            Label {
                Layout.topMargin: constants.paddingLarge
                text: qsTr("Name lookups")
                enabled: doh_endpoint_tf.enabled
            }

            TextField {
                id: doh_endpoint_tf
                Layout.fillWidth: true
                Layout.rightMargin: constants.paddingLarge
                enabled: proxy_enabled_cb.checked
                inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                placeholderText: qsTr("DoH endpoint")
                property bool valid: Network.isValidDohEndpoint(text)
                color: enabled
                    ? valid ? Material.foreground : constants.colorError
                    : Material.hintTextColor
            }
        }

        Button {
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: constants.paddingLarge
            enabled: proxy_enabled_cb.checked && !_probing
            text: qsTr('Detect Tor proxy')
            onClicked: {
                _probing = true
                Network.probeTor()
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
