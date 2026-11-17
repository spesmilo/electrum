import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// "Server settings" of the Material 3 GUI, opened by the Network page (NetworkPage); a full-screen dialog
// (M2-MAP F-1), as the classic one.
// repeats: components/ServerConfigDialog.qml:10-57 @ e6df7e1c8: the title; the server settings; Ok enabled by
// addressValid, writing Network.setServerParameters(server, auto_connect, one_server) from the connection mode
// and the address, then closing the dialog. Only the look differs.
// Differences: the settings are the Material 3 M3ServerConfig (the enum M3ServerConfig.Mode in place of
// ServerConnectModeComboBox.Mode, same order); M3ServerConfig is as high as its list of servers, so it sits in a
// Flickable with the address field kept above the on-screen keyboard (as wizard/WCServerConfig.qml, DESIGN-M2.md
// finding 8); Ok is the main button below the content; no icon in the header (Material 3 full-screen dialog).
// Strings keep the translation context of the classic file (qsTranslate('ServerConfigDialog', ...)).
M3FullScreenDialog {
    id: rootItem

    title: qsTranslate('ServerConfigDialog', 'Server settings')

    // scroll `flick` so that the whole of `item` (a descendant of its content) is visible, bottom first
    // (a copy of wizard/WizardComponent.qml ensureVisible())
    function ensureVisible(flick, item) {
        if (!flick || !item || !item.visible)
            return
        var p = item.mapToItem(flick.contentItem, 0, 0)
        var bottom = p.y + item.height + m3.space8
        if (bottom > flick.contentY + flick.height)
            flick.contentY = Math.min(Math.max(0, flick.contentHeight - flick.height), bottom - flick.height)
        else if (p.y < flick.contentY)
            flick.contentY = Math.max(0, p.y - m3.space8)
    }

    function _showFocused() {
        if (serverconfig.addressField.field.activeFocus)
            ensureVisible(flickable, serverconfig.addressField)
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            id: flickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentHeight: serverconfig.height + 2 * m3.space16
            interactive: height < contentHeight
            boundsBehavior: Flickable.StopAtBounds
            ScrollIndicator.vertical: ScrollIndicator {}

            // keep the focused field above the on-screen keyboard (the dialog shrinks with the keyboard)
            onHeightChanged: rootItem._showFocused()

            M3ServerConfig {
                id: serverconfig
                readonly property int margin: m3.screenMargin(rootItem.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
            }
        }

        // --- Ok (ServerConfigDialog.qml:39-55): below the content ---
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: okButton.implicitHeight + 2 * m3.space16
            color: m3.surface

            M3Button {
                id: okButton
                readonly property int margin: m3.screenMargin(rootItem.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
                variant: 'filled'
                size: 56
                icon.source: Qt.resolvedUrl('../../icons/m3/check.png')
                text: qsTranslate('ServerConfigDialog', 'Ok')
                enabled: serverconfig.addressValid
                onClicked: {
                    let auto_connect = serverconfig.serverConnectMode == M3ServerConfig.Mode.Autoconnect
                    let server = serverconfig.address
                    let one_server = serverconfig.serverConnectMode == M3ServerConfig.Mode.Single
                    Network.setServerParameters(server, auto_connect, one_server)
                    rootItem.close()
                }
            }
        }
    }

    Connections {
        target: serverconfig.addressField.field
        function onActiveFocusChanged() { Qt.callLater(rootItem._showFocused) }
    }
    // the error line below the field showed up (the field grew): keep it above the keyboard as well
    Connections {
        target: serverconfig.addressField
        function onHeightChanged() { Qt.callLater(rootItem._showFocused) }
    }
}
