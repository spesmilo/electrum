import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

// Material 3 page: proxy of the network wizard.
// repeats: components/wizard/WCProxyConfig.qml:7-24 @ e6df7e1c8 (valid, title, apply() with pc.toProxyDict(),
// proxy_enabled: false at the start).
WizardComponent {
    id: root
    valid: true
    title: qsTranslate('WCProxyConfig', 'Proxy')

    function apply() {
        wizard_data['proxy'] = pc.toProxyDict()
    }

    Flickable {
        id: flick
        anchors.fill: parent
        contentHeight: pc.height + m3.space16
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        // keep the focused field above the on-screen keyboard (the page shrinks with the keyboard)
        onHeightChanged: root._showFocused()

        M3ProxyConfig {
            id: pc
            width: parent.width
            y: m3.space8
            proxy_enabled: false
        }
    }

    function _showFocused() {
        if (pc.focusedField)
            ensureVisible(flick, pc.focusedField)
    }

    Connections {
        target: pc
        function onFocusedFieldChanged() { Qt.callLater(root._showFocused) }
    }
}
