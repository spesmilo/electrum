import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

// Proxy settings of the Material 3 GUI (DESIGN-M2-onboarding.md 3.5), for the network wizard and the network
// screens: switch "Enable Proxy", type SOCKS5/TOR or SOCKS4, address and port, authentication, Tor detection.
// repeats: classic controls/ProxyConfig.qml:8-136 @ e6df7e1c8 (the API proxy_enabled, proxy_type (index),
// proxy_address, proxy_port, username, password, proxy_type_map, toProxyDict(); the input method hints; every
// field but the switch enabled by proxy_enabled; Network.probeTor() and onTorProbeFinished).
// Differences: the type is a segmented button, the port field is narrow (96), "Authentication" is a section
// header; the strings keep the context of the classic file.
Item {
    id: pc

    implicitHeight: rootLayout.implicitHeight

    property bool proxy_enabled: false
    property int proxy_type: 0
    property alias proxy_address: addressField.text
    property alias proxy_port: portField.text
    property alias username: usernameField.text
    property alias password: passwordField.text

    property var proxy_type_map:  [
        { text: qsTranslate('ProxyConfig', 'SOCKS5/TOR'), value: 'socks5' },
        { text: qsTranslate('ProxyConfig', 'SOCKS4'), value: 'socks4' }
    ]

    // the field that has the focus (e.g. to scroll it into view), else null
    readonly property Item focusedField: addressField.field.activeFocus ? addressField
        : portField.field.activeFocus ? portField
        : usernameField.field.activeFocus ? usernameField
        : passwordField.field.activeFocus ? passwordField
        : null

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
        spacing: m3.space16

        M3ListGroup {
            Layout.fillWidth: true
            M3SwitchRow {
                headline: qsTranslate('ProxyConfig', 'Enable Proxy')
                checked: pc.proxy_enabled
                onUserToggled: (checked) => { pc.proxy_enabled = checked }
            }
        }

        M3SegmentedButton {
            Layout.fillWidth: true
            enabled: pc.proxy_enabled
            opacity: enabled ? 1 : m3.disabledContentOpacity
            model: pc.proxy_type_map
            currentValue: pc.proxy_type_map[pc.proxy_type]['value']
            onActivated: (value) => {
                for (var i = 0; i < pc.proxy_type_map.length; i++)
                    if (pc.proxy_type_map[i]['value'] === value)
                        pc.proxy_type = i
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: m3.space8

            M3TextField {
                id: addressField
                Layout.fillWidth: true
                enabled: pc.proxy_enabled
                label: qsTranslate('ProxyConfig', 'Address')
                inputMethodHints: Qt.ImhNoPredictiveText
            }

            M3TextField {
                id: portField
                Layout.preferredWidth: 96
                enabled: pc.proxy_enabled
                label: qsTranslate('ProxyConfig', 'Port')
                inputMethodHints: Qt.ImhDigitsOnly
            }
        }

        M3SectionHeader {
            Layout.fillWidth: true
            leftPadding: 0
            topPadding: 0
            bottomPadding: 0
            opacity: usernameField.enabled ? 1 : m3.disabledContentOpacity
            text: qsTranslate('ProxyConfig', 'Authentication')
        }

        M3TextField {
            id: usernameField
            Layout.fillWidth: true
            enabled: pc.proxy_enabled
            label: qsTranslate('ProxyConfig', 'Username')
            inputMethodHints: Qt.ImhNoPredictiveText
        }

        M3PasswordField {
            id: passwordField
            Layout.fillWidth: true
            enabled: pc.proxy_enabled
            label: qsTranslate('ProxyConfig', 'Password')
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: m3.space16

            M3Button {
                variant: 'tonal'
                enabled: pc.proxy_enabled && !_probing
                text: qsTranslate('ProxyConfig', 'Detect Tor proxy')
                onClicked: {
                    _probing = true
                    Network.probeTor()
                }
            }

            BusyIndicator {
                id: spinner
                Layout.preferredWidth: 40
                Layout.preferredHeight: 40
                running: visible
                visible: _probing
            }
        }
    }

    Connections {
        target: Network
        function onTorProbeFinished(host, port) {
            _probing = false
            if (host && port) {
                pc.proxy_type = 0
                proxy_port = ""+port
                proxy_address = host
            }
        }
    }
}
