import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "controls"

// Message and question dialog of the Material 3 GUI (app.messageDialog; M2-MAP F-2: an M3Dialog).
// repeats: components/MessageDialog.qml:8-86 @ e6df7e1c8 (the API: text, title, iconSource, yesno, richText,
// z: 1 by default and any z a caller sets (1001 above the crash dialog); the default title Question / Message;
// the text in plain or rich format, hidden when empty; Ok -> doAccept(), or No -> doReject() and Yes -> doAccept()
// when yesno).
// Differences: Material 3 look; the text scrolls (by a drag, mouse or finger) when it is longer than the free
// height, so the buttons stay visible; the text is not selectable (the classic read-only TextArea is selectable
// by mouse); the icon (M2-MAP F-5) is matched by the file name of `iconSource`, so the callers stay as they are:
// a classic or Material 3 `warning` -> the Material 3 `warning` glyph in m3.error; any other Material 3 glyph
// (icons/m3/) -> that glyph; `info`, `question` and the other colored classic icons -> no icon.
// Strings keep the translation context of the classic file (qsTranslate('MessageDialog', ...)).
M3Dialog {
    id: dialog

    title: yesno
        ? qsTranslate('MessageDialog', 'Question')
        : qsTranslate('MessageDialog', 'Message')

    property bool yesno: false
    property bool richText: false

    z: 1 // raise z so it also covers dialogs using overlay as parent

    // M2-MAP F-5: the glyph shown for `iconSource` ('' = no icon) and its color
    readonly property string _iconName: {
        var s = String(iconSource)
        if (s === '')
            return ''
        var name = s.substring(s.lastIndexOf('/') + 1).replace(/\.png$/, '')
        return name
    }
    readonly property bool _isWarning: _iconName === 'warning'
    readonly property string _glyph: _isWarning
        ? Qt.resolvedUrl('../../icons/m3/warning.png')
        : String(iconSource).indexOf('/icons/m3/') >= 0 ? String(iconSource) : ''

    // the dialog never grows past the free zone (keyboard included): the text scrolls instead
    // (centered: the same margin above and below, clear of the status bar and of the navigation bar; while the
    // keyboard is open the navigation bar is under it and the margin is smaller, the height is short then)
    height: Math.min(implicitHeight, parent
        ? parent.height - 2 * (app.keyboardFreeZone.state != 'visible'
            ? m3.space24 + Math.max(app.statusBarHeight, app.navigationBarHeight)
            : m3.space8 + app.statusBarHeight)
        : implicitHeight)

    // the header of M3DialogBase, with the icon of F-5 instead of `iconSource` as given
    header: ColumnLayout {
        spacing: m3.space16

        M3Icon {
            visible: dialog._glyph !== ''
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: m3.space24
            source: dialog._glyph
            color: dialog._isWarning ? m3.error : m3.secondary
        }

        M3Text {
            visible: dialog.title !== ''
            Layout.fillWidth: true
            leftPadding: m3.space24
            rightPadding: m3.space24
            topPadding: dialog._glyph !== '' ? 0 : m3.space24
            role: 'headlineSmall'
            wrapMode: Text.Wrap
            lineHeightMode: Text.ProportionalHeight
            lineHeight: 1.0
            horizontalAlignment: dialog._glyph !== '' ? Text.AlignHCenter : Text.AlignLeft
            text: dialog.title
        }
    }

    contentItem: Flickable {
        id: flick
        implicitHeight: dialog.text ? message.implicitHeight : 0
        contentHeight: message.implicitHeight
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        // a Text, not a selectable TextEdit: a TextEdit keeps the press, so a drag (mouse or finger) would select
        // or do nothing instead of scrolling the long text
        M3Text {
            id: message
            width: flick.width
            visible: dialog.text
            role: 'bodyMedium'
            color: m3.surfaceVariantOn
            wrapMode: Text.Wrap
            lineHeightMode: Text.ProportionalHeight
            lineHeight: 1.0
            textFormat: dialog.richText ? Text.RichText : Text.PlainText
            text: dialog.text
        }

        ScrollIndicator.vertical: ScrollIndicator { }
    }

    buttons: [
        M3Button {
            variant: 'text'
            text: qsTranslate('MessageDialog', 'Ok')
            visible: !dialog.yesno
            onClicked: dialog.doAccept()
        },
        M3Button {
            variant: 'text'
            text: qsTranslate('MessageDialog', 'Yes')
            visible: dialog.yesno
            onClicked: dialog.doAccept()
        },
        M3Button {
            variant: 'text'
            text: qsTranslate('MessageDialog', 'No')
            visible: dialog.yesno
            onClicked: dialog.doReject()
        }
    ]
}
