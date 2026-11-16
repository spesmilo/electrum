import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material

// Menu with the Material 3 theme set on the popup itself: a popup takes its style from the
// window (which stays dark for the classic screens), not from the item it is attached to.
Menu {
    id: root

    Material.theme: m3.dark ? Material.Dark : Material.Light
    Material.accent: m3.primary
    Material.primary: m3.primary
    Material.background: m3.surfaceContainerHigh
    Material.foreground: m3.surfaceOn

    parent: Overlay.overlay
    modal: true
    dim: true
    Overlay.modal: Rectangle {
        color: Qt.rgba(0, 0, 0, 0.12)
    }

    topPadding: 8
    bottomPadding: 8
    // as wide as the widest item (at least 200), up to the window width minus the margins: a translated
    // item is not elided (the Material 3 maximum of 280 is too narrow e.g. for Russian)
    width: Math.min(parent ? parent.width - 2 * m3.space8 : 280, Math.max(200, _widest + 48 + 24))
    font.pixelSize: m3.textStyle('bodyLarge').size

    property real _widest: 0
    function _updateWidth() {
        var w = 0
        for (var i = 0; i < count; i++) {
            var item = itemAt(i)
            if (item && item.text)
                w = Math.max(w, fontMetrics.advanceWidth(item.text))
        }
        _widest = w
    }
    onAboutToShow: _updateWidth()

    FontMetrics {
        id: fontMetrics
        font: root.font
    }

    background: Rectangle {
        implicitWidth: 200
        implicitHeight: 48
        radius: m3.radiusXS
        color: m3.surfaceContainerHigh
        border.width: m3.dark ? 0 : 1
        border.color: m3.outlineVariant
    }
}
