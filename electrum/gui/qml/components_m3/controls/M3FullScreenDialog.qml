import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

// Material 3 full-screen dialog: for dialogs that an app.* factory creates or that return their
// result by a signal (accepted, finalizer, ...), so the callers keep the classic API (createObject, open,
// accepted.connect, doAccept/doReject/doClose). Built on M3DialogBase: it is in app.activeDialogs (the Android
// back button closes it, unless allowClose is false) and shrinks with the keyboard (keyboardFreeZone).
// Top bar (64, surface): close button (X) on the left -> doReject(), the title (titleLarge), the optional
// `headerActions` (icon buttons) and the main action as a text button (`actionText`, `actionEnabled`) on the
// right -> actionTriggered(), then doAccept() unless `acceptOnAction` is false. Without `actionText` the main
// action, if any, is a button inside the content (as the classic screens with a bottom button).
// The content is the contentItem (the default property): a page-like body, scroll it yourself
// (Flickable/ScrollView), as the classic full-screen dialogs do.
M3DialogBase {
    id: dialog

    property string actionText
    property bool actionEnabled: true
    property bool acceptOnAction: true
    property list<Item> headerActions

    signal actionTriggered()

    function triggerAction() {
        dialog.actionTriggered()
        if (dialog.acceptOnAction)
            dialog.doAccept()
    }

    x: 0
    y: 0
    width: parent.width
    height: parent.height
    padding: 0
    topPadding: 0
    // the strip below the content for the Android navigation bar (needsSystemBarPadding, M3DialogBase)
    bottomPadding: needsSystemBarPadding && app.keyboardFreeZone.state != 'visible' ? app.navigationBarHeight : 0

    Overlay.modal: Rectangle {
        color: m3.scrimColor
    }

    background: Rectangle {
        color: m3.surface
    }

    header: ColumnLayout {
        spacing: 0

        // Add top padding for status bar on Android when using edge-to-edge
        Item {
            visible: dialog.needsSystemBarPadding && app.statusBarHeight > 0
            Layout.fillWidth: true
            Layout.preferredHeight: app.statusBarHeight
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.preferredHeight: m3.topAppBarHeight
            Layout.leftMargin: 4
            Layout.rightMargin: m3.space8
            spacing: 0

            M3IconButton {
                visible: dialog.allowClose
                tooltip: qsTr('Close')
                icon.source: Qt.resolvedUrl('../../../icons/m3/close.png')
                icon.color: m3.surfaceOn
                onClicked: dialog.doReject()
            }

            M3Text {
                Layout.fillWidth: true
                Layout.leftMargin: dialog.allowClose ? 4 : 12
                role: 'titleLarge'
                elide: Text.ElideRight
                text: dialog.title
            }

            Row {
                Layout.alignment: Qt.AlignVCenter
                visible: dialog.headerActions.length > 0
                children: dialog.headerActions
            }

            M3Button {
                visible: dialog.actionText !== ''
                Layout.alignment: Qt.AlignVCenter
                variant: 'text'
                text: dialog.actionText
                enabled: dialog.actionEnabled
                onClicked: dialog.triggerAction()
            }
        }
    }
}
