import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// Settings tab. Placeholder until the Material 3 settings screen: Appearance (interface style,
// theme), one display setting, and the classic Preferences, Network and About screens.
Item {
    id: root

    Flickable {
        anchors.fill: parent
        contentHeight: column.implicitHeight + 2 * m3.space16
        clip: true
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: column
            y: m3.space8
            width: Math.min(parent.width, m3.maxContentWidth) - 2 * m3.screenMargin(parent.width)
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: 0

            M3SectionHeader {
                text: qsTr('Appearance')
            }

            M3ListGroup {
                Layout.fillWidth: true

                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.margins: m3.space16
                    spacing: m3.space8

                    M3Text {
                        role: 'bodyLarge'
                        text: qsTr('Interface style')
                    }
                    M3SegmentedButton {
                        Layout.fillWidth: true
                        model: [
                            { text: qsTr('Classic'), value: 'classic' },
                            { text: qsTr('Material 3'), value: 'material3' }
                        ]
                        // the saved setting; this GUI runs Material 3 until restarted
                        currentValue: Config.uiStyle == 'material3' ? 'material3' : 'classic'
                        onActivated: (value) => {
                            if (value == 'classic')
                                app.showRestartDialog()  // writes the setting unless cancelled
                            else
                                Config.uiStyle = 'material3'
                        }
                    }
                    M3Text {
                        Layout.fillWidth: true
                        role: 'bodySmall'
                        color: m3.surfaceVariantOn
                        wrapMode: Text.Wrap
                        text: Config.uiStyle == 'material3'
                            ? qsTr('Applies after restart')
                            : qsTr('Now: Material 3; after restart: Classic')
                    }
                }

                M3SelectRow {
                    headline: qsTr('Theme')
                    leadingIcon: Qt.resolvedUrl('../../icons/m3/settings.png')
                    model: [
                        { text: qsTr('System'), value: 'system' },
                        { text: qsTr('Light'), value: 'light' },
                        { text: qsTr('Dark'), value: 'dark' }
                    ]
                    currentValue: Config.m3Theme == 'light' || Config.m3Theme == 'dark' ? Config.m3Theme : 'system'
                    onSelected: (value) => { Config.m3Theme = value }
                }

                M3SwitchRow {
                    headline: qsTr('Thousands separator')
                    supporting: qsTranslate('Preferences', 'Add thousands separators to bitcoin amounts')
                    checked: Config.thousandsSeparator
                    onUserToggled: (checked) => { Config.thousandsSeparator = checked }
                }
            }

            M3SectionHeader {
                text: qsTr('More')
                Layout.topMargin: m3.space8
            }

            M3ListGroup {
                Layout.fillWidth: true

                M3ListItem {
                    headline: qsTr('Preferences')
                    supporting: qsTr('All settings (classic screen)')
                    leadingIcon: Qt.resolvedUrl('../../icons/m3/settings.png')
                    trailing: chevron
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/Preferences.qml'))
                }
                M3ListItem {
                    headline: qsTr('Network')
                    supporting: Network.isConnected ? Network.server : qsTr('Disconnected')
                    leadingIcon: Qt.resolvedUrl(Network.isConnected ? '../../icons/m3/sync.png' : '../../icons/m3/cloud_off.png')
                    trailing: chevron
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/NetworkOverview.qml'))
                }
                M3ListItem {
                    headline: qsTranslate('main', 'About')
                    leadingIcon: Qt.resolvedUrl('../../icons/m3/info.png')
                    trailing: chevron
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/About.qml'))
                }
            }

            Flow {
                Layout.fillWidth: true
                Layout.topMargin: m3.space16
                spacing: m3.space8

                M3Chip {
                    visible: Network.isTestNet
                    tone: 'tertiary'
                    iconSource: Qt.resolvedUrl('../../icons/m3/info.png')
                    text: Network.networkName
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/NetworkOverview.qml'))
                }
                M3Chip {
                    tone: Network.isConnected ? '' : 'error'
                    iconSource: Qt.resolvedUrl(Network.isConnected ? '../../icons/m3/check_circle.png' : '../../icons/m3/cloud_off.png')
                    text: Network.isConnected ? qsTr('Connected') : qsTr('Disconnected')
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/NetworkOverview.qml'))
                }
            }
        }
    }

    Component {
        id: chevron
        M3Icon {
            source: Qt.resolvedUrl('../../icons/m3/chevron_right.png')
            color: m3.surfaceVariantOn
        }
    }
}
