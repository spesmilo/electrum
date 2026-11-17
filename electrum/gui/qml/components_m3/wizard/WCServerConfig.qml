import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

// Material 3 page: server of the network wizard.
// repeats: components/wizard/WCServerConfig.qml:7-27 @ e6df7e1c8 (valid by sc.addressValid, last, title, apply()).
// The server settings and the list scroll together, so the address field can be scrolled above the
// on-screen keyboard (DESIGN-M2.md finding 8), also once the error text below it shows up.
WizardComponent {
    id: root
    valid: sc.addressValid
    last: true
    title: qsTranslate('WCServerConfig', 'Server')

    function apply() {
        wizard_data['server'] = sc.address
        wizard_data['autoconnect'] = sc.serverConnectMode == M3ServerConfig.Mode.Autoconnect
        wizard_data['one_server'] = sc.serverConnectMode == M3ServerConfig.Mode.Single
    }

    Flickable {
        id: flick
        anchors.fill: parent
        contentHeight: sc.height + m3.space16
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        // keep the focused field above the on-screen keyboard (the page shrinks with the keyboard)
        onHeightChanged: root._showFocused()

        M3ServerConfig {
            id: sc
            width: parent.width
            y: m3.space8
        }
    }

    function _showFocused() {
        if (sc.addressField.field.activeFocus)
            ensureVisible(flick, sc.addressField)
    }

    Connections {
        target: sc.addressField.field
        function onActiveFocusChanged() { Qt.callLater(root._showFocused) }
    }
    // the error line below the field showed up (the field grew): keep it above the keyboard as well
    Connections {
        target: sc.addressField
        function onHeightChanged() { Qt.callLater(root._showFocused) }
    }
}
