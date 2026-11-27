import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

// Server settings of the Material 3 GUI, for the network wizard and the network
// screens: connection mode, server address, the list of known servers. The whole control is as high as its
// content (the list does not scroll by itself): put it into a Flickable, so the field and the list scroll
// together and the field can be scrolled above the on-screen keyboard.
// repeats: classic controls/ServerConfig.qml:12-138, ServerConnectModeComboBox.qml:9-37 and
// ServerDelegate.qml (the API showAutoselectServer, address, serverConnectMode, addressValid; the
// enum Mode; the initial mode (Manual on the first start, else from Network.autoConnect / oneServer); the address
// cleared in Autoconnect; the address field disabled in Autoconnect and validated by
// Network.isValidServerAddress; the help text of the connection modes; Network.serverListModel with the sections
// by chain; a tap on a server puts its name into the field; address = Network.server at the start; the address
// validated at the end of the start, so an empty address in Manual mode is invalid from the first frame).
// Differences: the mode is one row (M3SelectRow, the choice in a dialog), the invalid address shows the error
// text "Invalid server address" (new string) once the user edited the field, not a red fill from the start;
// a server row shows a check when primary and a dot when connected.
Item {
    id: root

    enum Mode {
        Autoconnect,
        Manual,
        Single
    }

    property bool showAutoselectServer: true
    property alias address: address_tf.text
    property int serverConnectMode: M3ServerConfig.Mode.Manual
    readonly property bool addressValid: address_tf.valid
    // the address field, e.g. to scroll it into view
    readonly property Item addressField: address_tf

    property bool _edited: false

    implicitHeight: rootLayout.implicitHeight

    readonly property var _modes: [
        { text: qsTranslate('ServerConnectModeComboBox', 'Auto-connect'), value: M3ServerConfig.Mode.Autoconnect },
        { text: qsTranslate('ServerConnectModeComboBox', 'Manual server selection'), value: M3ServerConfig.Mode.Manual },
        { text: qsTranslate('ServerConnectModeComboBox', 'Connect only to a single server'), value: M3ServerConfig.Mode.Single }
    ]

    onServerConnectModeChanged: {
        if (serverConnectMode == M3ServerConfig.Mode.Autoconnect) {
            address_tf.text = ""
        }
    }

    ColumnLayout {
        id: rootLayout

        width: parent.width
        spacing: m3.space16

        RowLayout {
            Layout.fillWidth: true
            spacing: m3.space4

            M3ListGroup {
                Layout.fillWidth: true
                M3SelectRow {
                    headline: qsTranslate('ServerConfig', 'Connection mode')
                    model: root._modes
                    currentValue: root.serverConnectMode
                    onSelected: (value) => { root.serverConnectMode = value }
                }
            }

            M3HelpButton {
                heading: qsTranslate('ServerConfig', 'Connection mode') + ':'
                helptext: Config.getTranslatedMessage('MSG_CONNECTMODE_SERVER_HELP') + '<br/><br/>' +
                    Config.getTranslatedMessage('MSG_CONNECTMODE_NODES_HELP') + '<ul>' +
                    '<li><b>' + Config.getTranslatedMessage('MSG_CONNECTMODE_AUTOCONNECT') +
                    '</b>: ' + Config.getTranslatedMessage('MSG_CONNECTMODE_AUTOCONNECT_HELP') + '</li>' +
                    '<li><b>' + Config.getTranslatedMessage('MSG_CONNECTMODE_MANUAL') +
                    '</b>: ' + Config.getTranslatedMessage('MSG_CONNECTMODE_MANUAL_HELP') + '</li>' +
                    '<li><b>' + Config.getTranslatedMessage('MSG_CONNECTMODE_ONESERVER') +
                    '</b>: ' + Config.getTranslatedMessage('MSG_CONNECTMODE_ONESERVER_HELP') + '</li>' +
                    '</ul>'
            }
        }

        M3TextField {
            id: address_tf
            Layout.fillWidth: true

            enabled: root.serverConnectMode != M3ServerConfig.Mode.Autoconnect
            inputMethodHints: Qt.ImhNoPredictiveText
            label: qsTranslate('ServerConfig', 'Server')
            errorText: !valid && root._edited ? qsTr('Invalid server address') : ''

            property bool valid: true

            function validate() {
                if (!enabled) {
                    valid = true
                    return
                }
                valid = Network.isValidServerAddress(address_tf.text)
            }

            onTextChanged: validate()
            onEnabledChanged: validate()
        }

        Connections {
            target: address_tf.field
            function onTextEdited() { root._edited = true }
        }

        M3SectionHeader {
            Layout.fillWidth: true
            leftPadding: 0
            bottomPadding: 0
            text: qsTranslate('ServerConfig', 'Servers')
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: serversListView.contentHeight
            color: m3.surfaceContainerLow
            radius: m3.radiusL
            clip: true

            ListView {
                id: serversListView
                anchors.fill: parent
                interactive: false
                model: Network.serverListModel
                delegate: M3ListItem {
                    width: ListView.view.width
                    headline: model.address
                    leading: Component {
                        Item {
                            implicitWidth: 24
                            implicitHeight: 24
                            M3Icon {
                                anchors.fill: parent
                                visible: model.is_primary
                                source: Qt.resolvedUrl('../../../icons/m3/check.png')
                                color: m3.primary
                            }
                        }
                    }
                    trailing: Component {
                        Rectangle {
                            implicitWidth: 8
                            implicitHeight: 8
                            radius: 4
                            color: model.is_connected ? m3.success : 'transparent'
                        }
                    }
                    onClicked: {
                        address_tf.text = model.name
                    }
                }

                section.property: 'chain'
                section.criteria: ViewSection.FullString
                section.delegate: M3Text {
                    width: ListView.view.width
                    required property string section
                    role: 'labelLarge'
                    color: m3.primary
                    leftPadding: m3.space16
                    topPadding: m3.space12
                    bottomPadding: m3.space4
                    text: section
                        ? serversListView.model.chaintips > 1
                            ? qsTranslate('ServerConfig', 'Connected @%1').arg(section)
                            : qsTranslate('ServerConfig', 'Connected')
                        : qsTranslate('ServerConfig', 'Other known servers')
                }
            }
        }
    }

    Component.onCompleted: {
        if (!Network.autoConnectDefined) { // initial setup
            root.serverConnectMode = M3ServerConfig.Mode.Manual
        } else {
            root.serverConnectMode = Network.autoConnect
                ? M3ServerConfig.Mode.Autoconnect
                : Network.oneServer
                    ? M3ServerConfig.Mode.Single
                    : M3ServerConfig.Mode.Manual
        }
        root.address = Network.server
        // the classic combo box starts at Auto-connect and then moves to the mode above, so the field turns
        // enabled and validates itself (onEnabledChanged); here the mode may start right away (Manual on the
        // first start) and neither the text nor `enabled` changes: validate once, as the classic ends up doing
        // (an empty address in Manual mode is invalid, Next stays disabled)
        address_tf.validate()
    }
}
