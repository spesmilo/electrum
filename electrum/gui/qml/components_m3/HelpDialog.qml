import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "controls"

// Help dialog of the Material 3 GUI (app.helpDialog, opened by M3HelpButton and the classic HelpButton; an M3Dialog).
// repeats: components/controls/HelpDialog.qml:5-75 (the API: heading, text; z: 1 so it also covers
// dialogs using the overlay as parent; the text in rich format; it closes by the back button or a tap outside).
// Differences: Material 3 look: the heading is the headline of the dialog (the classic draws it underlined and
// italic next to the info icon), the text scrolls when it is longer than the free height, and a Close text button
// (doClose(), as the back button; shown only when allowClose).
M3Dialog {
    id: dialog

    property string heading

    title: dialog.heading

    z: 1 // raise z so it also covers dialogs using overlay as parent

    // the dialog never grows past the free zone: the text scrolls instead
    // (centered: the same margin above and below, clear of the status bar and of the navigation bar; while the
    // keyboard is open the navigation bar is under it and the margin is smaller, the height is short then)
    height: Math.min(implicitHeight, parent
        ? parent.height - 2 * (app.keyboardFreeZone.state != 'visible'
            ? m3.space24 + Math.max(app.statusBarHeight, app.navigationBarHeight)
            : m3.space8 + app.statusBarHeight)
        : implicitHeight)

    contentItem: Flickable {
        id: flick
        implicitHeight: message.implicitHeight
        contentHeight: message.implicitHeight
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        M3Text {
            id: message
            width: flick.width
            role: 'bodyMedium'
            color: m3.surfaceVariantOn
            wrapMode: Text.Wrap
            lineHeightMode: Text.ProportionalHeight
            lineHeight: 1.0
            textFormat: Text.RichText
            text: dialog.text
        }

        ScrollIndicator.vertical: ScrollIndicator { }
    }

    buttons: [
        M3Button {
            variant: 'text'
            text: qsTr('Close')
            visible: dialog.allowClose
            onClicked: dialog.doClose()
        }
    ]
}
