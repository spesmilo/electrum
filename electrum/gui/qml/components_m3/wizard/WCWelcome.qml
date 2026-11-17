import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

// Material 3 page: first page of the network wizard (proxy and server: use the defaults or configure).
// repeats: components/wizard/WCWelcome.qml:7-55 @ e6df7e1c8 (valid, wizard_title, apply(), checkIsLast() on every
// change of the two options, the strings). The checkboxes config_proxy / config_server are switch rows; their
// state is kept in configProxy / configServer, read by the same apply().
WizardComponent {
    id: root
    valid: true
    wizard_title: qsTranslate('WCWelcome', 'Network Configuration')

    property bool configProxy: false
    property bool configServer: false

    onConfigProxyChanged: checkIsLast()
    onConfigServerChanged: checkIsLast()

    function apply() {
        wizard_data['use_defaults'] = !configProxy && !configServer
        wizard_data['want_proxy'] = configProxy
        wizard_data['autoconnect'] = !configServer
    }

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height + m3.space16
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: m3.space16

            M3Text {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                role: 'titleMedium'
                wrapMode: Text.Wrap
                text: qsTranslate('WCWelcome', 'Optional settings to customize your network connection') + ':'
            }

            M3ListGroup {
                Layout.fillWidth: true
                M3SwitchRow {
                    headline: qsTranslate('WCWelcome', 'Configure Proxy')
                    checked: root.configProxy
                    onUserToggled: (checked) => { root.configProxy = checked }
                }
                M3SwitchRow {
                    headline: qsTranslate('WCWelcome', 'Select Server')
                    checked: root.configServer
                    onUserToggled: (checked) => { root.configServer = checked }
                }
            }

            M3Text {
                Layout.fillWidth: true
                role: 'bodyMedium'
                color: m3.surfaceVariantOn
                wrapMode: Text.Wrap
                text: qsTranslate('WCWelcome', 'If you are unsure what this is, leave them unchecked and Electrum will automatically select servers.')
            }
        }
    }
}
