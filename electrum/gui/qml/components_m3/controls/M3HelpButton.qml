import QtQuick
import QtQuick.Controls

// "Help" icon button next to a field or a section: opens app.helpDialog with `heading` and `helptext`.
// repeats: components/controls/HelpButton.qml:6-20 @ e6df7e1c8 (heading, helptext, the app.helpDialog call).
// Differences: Material 3 icon button (48 touch target, 24 dp `help` glyph in onSurfaceVariant) instead of the
// colored classic info.png; the tooltip names the heading.
M3IconButton {
    id: root
    property string heading
    property string helptext

    tooltip: root.heading
    icon.source: Qt.resolvedUrl('../../../icons/m3/help.png')
    onClicked: {
        var dialog = app.helpDialog.createObject(app, {
            heading: root.heading,
            text: root.helptext
        })
        dialog.open()
    }
}
