import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "../../components/controls" as CC

// Material 3 basic dialog. Built on the classic dialog base (CC.ElDialog), so it takes part in
// app.activeDialogs and the Android back button, and lives in app.keyboardFreeZone.
// The theme is set on the popup itself: a popup takes its style from the window, which stays dark.
// Content: `text` (supporting text) or an own contentItem; buttons: `buttons` (right aligned).
CC.ElDialog {
    id: dialog

    property string text
    property list<Item> buttons

    needsSystemBarPadding: false
    anchors.centerIn: parent
    width: Math.min(560, parent.width - 2 * m3.space24)
    padding: m3.space24
    topPadding: m3.space16
    bottomPadding: m3.space8

    Material.theme: m3.dark ? Material.Dark : Material.Light
    Material.accent: m3.primary
    Material.primary: m3.primary
    Material.background: m3.surfaceContainerHigh
    Material.foreground: m3.surfaceOn
    Material.roundedScale: Material.ExtraLargeScale

    Overlay.modal: Rectangle {
        color: m3.scrimColor
    }

    background: Rectangle {
        color: m3.surfaceContainerHigh
        radius: m3.radiusXL
    }

    header: M3Text {
        visible: dialog.title
        leftPadding: m3.space24
        rightPadding: m3.space24
        topPadding: m3.space24
        role: 'headlineSmall'
        wrapMode: Text.Wrap
        lineHeightMode: Text.ProportionalHeight
        lineHeight: 1.0
        text: dialog.title
    }

    contentItem: M3Text {
        role: 'bodyMedium'
        color: m3.surfaceVariantOn
        wrapMode: Text.Wrap
        lineHeightMode: Text.ProportionalHeight
        lineHeight: 1.0
        text: dialog.text
    }

    footer: Item {
        implicitHeight: buttonRow.implicitHeight + m3.space16
        Flow {
            id: buttonRow
            anchors.right: parent.right
            anchors.rightMargin: m3.space16
            anchors.left: parent.left
            anchors.leftMargin: m3.space16
            layoutDirection: Qt.RightToLeft
            spacing: m3.space8
            children: dialog.buttons
        }
    }
}
