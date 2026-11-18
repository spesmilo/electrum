import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

// Base of every Material 3 dialog (M3Dialog, M3FullScreenDialog), without the classic controls.
// repeats: components/controls/ElDialog.qml:1-77 @ e6df7e1c8 (allowClose, iconSource, resizeWithKeyboard,
// needsSystemBarPadding, doClose/doAccept/doReject, parent keyboardFreeZone, modal, closePolicy, the tap on
// the background that hides the keyboard, app.activeDialogs). The dialog puts itself into the same
// app.activeDialogs as the classic dialogs, so the Android back button (main.qml onClosing) closes the top
// dialog first, Material 3 or classic.
// Differences: the theme is set on the popup itself (a popup takes its style from the window, which stays dark
// for the classic screens), the scrim is m3.scrimColor, and the default header is a Material 3 headline with
// the optional icon (ElDialog.qml:78-122 draws the classic header with `constants`), and the tap on the
// background takes the press for itself (see the TapHandler).
Dialog {
    id: abstractdialog

    property bool allowClose: true
    property string iconSource
    property bool resizeWithKeyboard: true
    // inheriting classes can set needsSystemBarPadding this false to disable padding
    property bool needsSystemBarPadding: true

    property bool _result: false
    // workaround: remember opened state, to inhibit closed -> closed event
    property bool _wasOpened: false

    // Add bottom padding for Android navigation bar if needed
    bottomPadding: needsSystemBarPadding && app.keyboardFreeZone.state != 'visible' ? app.navigationBarHeight : 0

    // called to finally close dialog after checks by onClosing handler in main.qml
    function doClose() {
        doReject()
    }

    // avoid potential multiple signals, only emit once
    function doAccept() {
        if (_result)
            return
        _result = true
        accept()
    }

    // avoid potential multiple signals, only emit once
    function doReject() {
        if (_result)
            return
        _result = true
        reject()
    }

    parent: resizeWithKeyboard ? app.keyboardFreeZone : Overlay.overlay
    modal: true
    Overlay.modal: Rectangle {
        color: m3.scrimColor
    }

    closePolicy: allowClose
        ? Popup.CloseOnEscape | Popup.CloseOnPressOutside
        : Popup.NoAutoClose

    Material.theme: m3.dark ? Material.Dark : Material.Light
    Material.accent: m3.primary
    Material.primary: m3.primary
    Material.background: m3.surfaceContainerHigh
    Material.foreground: m3.surfaceOn
    Material.roundedScale: Material.ExtraLargeScale

    TapHandler {  // close keyboard when tapping on the empty background
        parent: abstractdialog.background
        // An exclusive grab on press: with the default policy (DragThreshold) the handler only grabs passively
        // and leaves the press unaccepted, so a mouse click on the empty background went on to the pointer
        // handlers of the page under the modal dialog (a clickable M3Card opened its page behind the dialog).
        gesturePolicy: TapHandler.ReleaseWithinBounds
        onTapped: (eventPoint, button) => {
            // This policy keeps the point after it moved: a drag released farther than the drag distance from
            // where it was pressed is not a tap (the default policy also cancels a drag that moved that far and
            // came back; here such a drag still taps).
            if (Math.abs(eventPoint.scenePosition.x - eventPoint.scenePressPosition.x) > Qt.styleHints.startDragDistance
                    || Math.abs(eventPoint.scenePosition.y - eventPoint.scenePressPosition.y) > Qt.styleHints.startDragDistance)
                return
            // Release input focus so tapping the same field opens the keyboard again.
            abstractdialog.contentItem.forceActiveFocus(Qt.MouseFocusReason)
            Qt.inputMethod.hide()
        }
    }

    onOpenedChanged: {
        if (opened) {
            app.activeDialogs.push(abstractdialog)
            _wasOpened = true
            _result = false
        } else {
            if (!_wasOpened)
                return
            if (app.activeDialogs.indexOf(abstractdialog) < 0) {
                console.log('dialog should exist in activeDialogs!')
                app.activeDialogs.pop()
                return
            }
            app.activeDialogs.splice(app.activeDialogs.indexOf(abstractdialog),1)
        }
    }

    background: Rectangle {
        color: m3.surfaceContainerHigh
        radius: m3.radiusXL
    }

    // M3 basic dialog header: optional icon (24, secondary) centered above the headline, then the headline
    // (headlineSmall; centered when there is an icon, as the Material 3 dialog with a hero icon)
    header: ColumnLayout {
        spacing: m3.space16

        // Add top padding for status bar on Android when using edge-to-edge
        Item {
            visible: needsSystemBarPadding && app.statusBarHeight > 0
            Layout.fillWidth: true
            Layout.preferredHeight: app.statusBarHeight
        }

        M3Icon {
            visible: abstractdialog.iconSource !== ''
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: m3.space24
            source: abstractdialog.iconSource
            color: m3.secondary
        }

        M3Text {
            visible: abstractdialog.title !== ''
            Layout.fillWidth: true
            leftPadding: m3.space24
            rightPadding: m3.space24
            topPadding: abstractdialog.iconSource !== '' ? 0 : m3.space24
            role: 'headlineSmall'
            wrapMode: Text.Wrap
            lineHeightMode: Text.ProportionalHeight
            lineHeight: 1.0
            horizontalAlignment: abstractdialog.iconSource !== '' ? Text.AlignHCenter : Text.AlignLeft
            text: abstractdialog.title
        }
    }
}
