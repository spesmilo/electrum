import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// "Proxy settings" of the Material 3 GUI, opened by the Network page (NetworkPage); a full-screen dialog,
// as the classic one.
// repeats: components/ProxyConfigDialog.qml:10-63: the title; the proxy settings filled from
// Network.proxy when the dialog is created (enabled, host, port, user, password, the index of the mode in
// proxy_type_map); Ok writes Network.proxy = toProxyDict() and closes the dialog. Only the look differs.
// Differences: the settings are the Material 3 M3ProxyConfig, in a Flickable with the focused field kept above the
// on-screen keyboard (as wizard/WCProxyConfig.qml); a mode that is not in proxy_type_map gives the first type
// (Math.max(0, ...)) instead of -1, which M3ProxyConfig cannot show; Ok is the
// main button below the content; no icon in the header (Material 3 full-screen dialog); a user or password that
// is None gives an empty field (the classic assignment of undefined fails and skips the rest of the filling).
// Strings keep the translation context of the classic file (qsTranslate('ProxyConfigDialog', ...)).
M3FullScreenDialog {
    id: rootItem

    title: qsTranslate('ProxyConfigDialog', 'Proxy settings')

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
        if (proxyconfig.focusedField)
            ensureVisible(flickable, proxyconfig.focusedField)
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            id: flickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentHeight: proxyconfig.height + 2 * m3.space16
            interactive: height < contentHeight
            boundsBehavior: Flickable.StopAtBounds
            ScrollIndicator.vertical: ScrollIndicator {}

            // keep the focused field above the on-screen keyboard (the dialog shrinks with the keyboard)
            onHeightChanged: rootItem._showFocused()

            M3ProxyConfig {
                id: proxyconfig
                readonly property int margin: m3.screenMargin(rootItem.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
            }
        }

        // --- Ok (ProxyConfigDialog.qml:35-48): below the content ---
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
                text: qsTranslate('ProxyConfigDialog', 'Ok')
                onClicked: {
                    Network.proxy = proxyconfig.toProxyDict()
                    rootItem.close()
                }
            }
        }
    }

    Connections {
        target: proxyconfig
        function onFocusedFieldChanged() { Qt.callLater(rootItem._showFocused) }
    }

    // ProxyConfigDialog.qml:51-62
    Component.onCompleted: {
        var p = Network.proxy

        proxyconfig.proxy_enabled = p['enabled']
        proxyconfig.proxy_address = p['host']
        proxyconfig.proxy_port = p['port']
        // M3: user and password are None (undefined here) without authentication; the classic assignment fails
        // there and stops this handler before the type is set
        proxyconfig.username = p['user'] || ''
        proxyconfig.password = p['password'] || ''
        // M3: an unknown mode gives the first type, not -1 (M3ProxyConfig binds proxy_type_map[proxy_type])
        proxyconfig.proxy_type = Math.max(0, proxyconfig.proxy_type_map.map(function(x) {
            return x.value
        }).indexOf(p['mode']))
    }
}
