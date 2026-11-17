import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

// Material 3 basic dialog. Built on M3DialogBase (the behavior of the classic ElDialog), so it takes part in
// app.activeDialogs and the Android back button, and lives in app.keyboardFreeZone; the theme, the scrim, the
// background and the header (headline, optional `iconSource` above it) come from the base.
// Content: `text` (supporting text) or an own contentItem; buttons: `buttons` (right aligned).
M3DialogBase {
    id: dialog

    property string text
    property list<Item> buttons

    needsSystemBarPadding: false
    anchors.centerIn: parent
    width: Math.min(560, parent.width - 2 * m3.space24)
    padding: m3.space24
    topPadding: m3.space16
    bottomPadding: m3.space8

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
