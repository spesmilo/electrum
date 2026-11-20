import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// Notification of the Material 3 GUI: a snackbar, the instance `notificationPopup` in main.qml,
// shown by AppController.onUserNotify and by a payment that succeeded or failed.
// repeats: components/NotificationPopup.qml:7-115 (the API: show(wallet_name, message), message,
// wallet_name; shown for 5 s, a new show() replaces the text; the wallet name only when it is not the current
// wallet; clicks on it do not reach the page below; an Item of the window, not a Popup, so it is not in
// app.activeDialogs and the back button does not close it).
// Differences: at the bottom of the window, on m3.inverseSurface, above the system
// navigation bar (app.navigationBarHeight, while the keyboard is hidden), above the bottom navigation when the
// Material 3 wallet root is on top of the stack, plus m3.space8; the text is `message`, the wallet name a
// labelSmall line above it; it slides up and fades in instead of the classic drop-down from the top.
// A new show() restarts the 5 s (closetimer.restart()): the classic calls start(), which does nothing on a running
// Timer, so there a second notification is hidden 5 s after the FIRST one. A tap on the snackbar hides it at once
// (the classic only swallows the tap; here the snackbar may lie over the bottom buttons of a page).
Item {
    id: root

    property string message
    property string wallet_name
    property bool _hide: true

    // the bottom of the free content area: the window content without the top app bar and the keyboard
    readonly property real _bottom: Math.min(parent ? parent.height : 0,
        app.keyboardFreeZone.height - (app.header ? app.header.height : 0))
    readonly property bool _walletRootOnTop: app.stack.currentItem
        ? app.stack.currentItem.m3WalletRoot === true
        : false
    readonly property real _bottomOffset: (app.keyboardFreeZone.state != 'visible' ? app.navigationBarHeight : 0)
        + (_walletRootOnTop ? m3.navigationBarHeight : 0)
        + m3.space8

    readonly property bool _showWallet: root.wallet_name !== ''
        && !(Daemon.currentWallet && root.wallet_name == Daemon.currentWallet.name)

    height: snackbar.height
    y: _bottom - _bottomOffset - height + (_hide ? m3.space16 : 0)
    z: 100
    visible: opacity > 0
    opacity: _hide ? 0 : 1

    Behavior on opacity { NumberAnimation { duration: 200; easing.type: Easing.OutQuad } }
    Behavior on y { NumberAnimation { duration: 200; easing.type: Easing.OutQuad } }

    function show(wallet_name, message) {
        root.wallet_name = wallet_name
        root.message = message
        root._hide = false
        closetimer.restart()
    }

    Rectangle {
        id: snackbar
        readonly property int margin: m3.space16
        width: Math.min(600, root.width - 2 * margin)
        x: (root.width - width) / 2
        height: layout.implicitHeight + 2 * m3.space12
        radius: m3.radiusXS
        color: m3.inverseSurface

        // capture all clicks; a tap hides the snackbar (it may cover the bottom buttons of a page)
        MouseArea {
            anchors.fill: parent
            enabled: !root._hide
            onClicked: {
                closetimer.stop()
                root._hide = true
            }
        }

        ColumnLayout {
            id: layout
            x: m3.space16
            y: m3.space12
            width: parent.width - 2 * m3.space16
            spacing: m3.space4

            M3Text {
                Layout.fillWidth: true
                visible: root._showWallet
                role: 'labelSmall'
                color: m3.inversePrimary
                elide: Text.ElideRight
                text: root.wallet_name
            }

            M3Text {
                Layout.fillWidth: true
                role: 'bodyMedium'
                color: m3.inverseSurfaceOn
                wrapMode: Text.Wrap
                lineHeightMode: Text.ProportionalHeight
                lineHeight: 1.0
                text: root.message
            }
        }
    }

    Timer {
        id: closetimer
        interval: 5000
        repeat: false
        onTriggered: _hide = true
    }
}
