import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import QtQml 2.6
import QtMultimedia 5.6

import "controls"

ApplicationWindow
{
    id: app
    visible: true

    // dimensions ignored on android
    width: 480
    height: 800

    Material.theme: Material.Dark
    Material.primary: Material.Indigo
    Material.accent: Material.LightBlue
    font.pixelSize: constants.fontSizeMedium

    property Item constants: appconstants
    Constants { id: appconstants }

    property alias stack: mainStackView

    property variant activeDialogs: []

    header: ToolBar {
        id: toolbar

        RowLayout {
            anchors.fill: parent

            ToolButton {
                text: qsTr("‹")
                enabled: stack.depth > 1
                onClicked: stack.pop()
            }

            Image {
                Layout.alignment: Qt.AlignVCenter
                Layout.preferredWidth: constants.iconSizeLarge
                Layout.preferredHeight: constants.iconSizeLarge
                source: "../../icons/electrum.png"
            }

            Label {
                text: stack.currentItem.title
                elide: Label.ElideRight
                horizontalAlignment: Qt.AlignHCenter
                verticalAlignment: Qt.AlignVCenter
                Layout.fillWidth: true
                font.pixelSize: constants.fontSizeMedium
                font.bold: true
            }

            Item {
                visible: Network.isTestNet
                width: column.width
                height: column.height

                ColumnLayout {
                    id: column
                    spacing: 0
                    Image {
                        Layout.alignment: Qt.AlignHCenter
                        Layout.preferredWidth: constants.iconSizeSmall
                        Layout.preferredHeight: constants.iconSizeSmall
                        source: "../../icons/info.png"
                    }

                    Label {
                        id: networkNameLabel
                        text: Network.networkName
                        color: Material.accentColor
                        font.pixelSize: constants.fontSizeXSmall
                    }
                }
            }

            Image {
                Layout.preferredWidth: constants.iconSizeSmall
                Layout.preferredHeight: constants.iconSizeSmall
                visible: Daemon.currentWallet && Daemon.currentWallet.isWatchOnly
                source: '../../icons/eye1.png'
                scale: 1.5
            }

            NetworkStatusIndicator { }

            Rectangle {
                color: 'transparent'
                Layout.preferredWidth: constants.paddingSmall
                height: 1
                visible: !menuButton.visible
            }

            ToolButton {
                id: menuButton
                enabled: stack.currentItem && stack.currentItem.menu ? stack.currentItem.menu.count > 0 : false
                text: enabled ? qsTr("≡") : ''
                font.pixelSize: constants.fontSizeXLarge
                onClicked: {
                    stack.currentItem.menu.open()
                    // position the menu to the right
                    stack.currentItem.menu.x = toolbar.width - stack.currentItem.menu.width
                }
            }
        }
    }

    StackView {
        id: mainStackView
        anchors.fill: parent

        initialItem: Qt.resolvedUrl('WalletMainView.qml')
    }

    Timer {
        id: splashTimer
        interval: 10
        onTriggered: {
            splash.opacity = 0
        }
    }

    Splash {
        id: splash
        anchors.top: header.top
        anchors.bottom: app.contentItem.bottom
        width: app.width
        z: 1000

        Behavior on opacity {
            NumberAnimation { duration: 300 }
        }
    }

    property alias newWalletWizard: _newWalletWizard
    Component {
        id: _newWalletWizard
        NewWalletWizard {
            parent: Overlay.overlay
            Overlay.modal: Rectangle {
                color: "#aa000000"
            }
        }
    }

    property alias serverConnectWizard: _serverConnectWizard
    Component {
        id: _serverConnectWizard
        ServerConnectWizard {
            parent: Overlay.overlay
            Overlay.modal: Rectangle {
                color: "#aa000000"
            }
        }
    }

    property alias messageDialog: _messageDialog
    Component {
        id: _messageDialog
        MessageDialog {
            onClosed: destroy()
        }
    }

    property alias passwordDialog: _passwordDialog
    Component {
        id: _passwordDialog
        PasswordDialog {
            onClosed: destroy()
        }
    }

    property alias pinDialog: _pinDialog
    Component {
        id: _pinDialog
        Pin {
            onClosed: destroy()
        }
    }

    property alias genericShareDialog: _genericShareDialog
    Component {
        id: _genericShareDialog
        GenericShareDialog {
            onClosed: destroy()
        }
    }

    property alias openWalletDialog: _openWalletDialog
    Component {
        id: _openWalletDialog
        OpenWalletDialog {
            onClosed: destroy()
        }
    }

    property alias channelOpenProgressDialog: _channelOpenProgressDialog
    ChannelOpenProgressDialog {
        id: _channelOpenProgressDialog
    }

    NotificationPopup {
        id: notificationPopup
    }

    Component.onCompleted: {
        splashTimer.start()

        if (!Config.autoConnectDefined) {
            var dialog = serverConnectWizard.createObject(app)
            // without completed serverConnectWizard we can't start
            dialog.rejected.connect(function() {
                app.visible = false
                Qt.callLater(Qt.quit)
            })
            dialog.open()
        } else {
            Daemon.load_wallet()
        }
    }

    onClosing: {
        if (activeDialogs.length > 0) {
            var activeDialog = activeDialogs[activeDialogs.length - 1]
            if (activeDialog.allowClose) {
                activeDialog.close()
            } else {
                console.log('dialog disallowed close')
            }
            close.accepted = false
            return
        }
        if (stack.depth > 1) {
            close.accepted = false
            stack.pop()
        } else {
            // destroy most GUI components so that we don't dump so many null reference warnings on exit
            if (closeMsgTimer.running) {
                app.header.visible = false
                mainStackView.clear()
            } else {
                notificationPopup.show('Press Back again to exit')
                closeMsgTimer.start()
                close.accepted = false
            }
        }
    }

    Timer {
        id: closeMsgTimer
        interval: 5000
        repeat: false
    }

    Connections {
        target: Daemon
        function onWalletRequiresPassword() {
            console.log('wallet requires password')
            var dialog = openWalletDialog.createObject(app, { path: Daemon.path })
            dialog.open()
        }
        function onWalletOpenError(error) {
            console.log('wallet open error')
            var dialog = app.messageDialog.createObject(app, {'text': error})
            dialog.open()
        }
        function onAuthRequired(method) {
            handleAuthRequired(Daemon, method)
        }
    }

    Connections {
        target: AppController
        function onUserNotify(message) {
            notificationPopup.show(message)
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onAuthRequired(method) {
            handleAuthRequired(Daemon.currentWallet, method)
        }
        // TODO: add to notification queue instead of barging through
        function onPaymentSucceeded(key) {
            notificationPopup.show(qsTr('Payment Succeeded'))
        }
        function onPaymentFailed(key, reason) {
            notificationPopup.show(qsTr('Payment Failed') + ': ' + reason)
        }
    }

    Connections {
        target: Config
        function onAuthRequired(method) {
            handleAuthRequired(Config, method)
        }
    }

    function handleAuthRequired(qtobject, method) {
        console.log('auth using method ' + method)
        if (method == 'wallet') {
            if (Daemon.currentWallet.verify_password('')) {
                // wallet has no password
                qtobject.authProceed()
            } else {
                var dialog = app.passwordDialog.createObject(app, {'title': qsTr('Enter current password')})
                dialog.accepted.connect(function() {
                    if (Daemon.currentWallet.verify_password(dialog.password)) {
                        qtobject.authProceed()
                    } else {
                        qtobject.authCancel()
                    }
                })
                dialog.rejected.connect(function() {
                    qtobject.authCancel()
                })
                dialog.open()
            }
        } else if (method == 'pin') {
            if (Config.pinCode == '') {
                // no PIN configured
                qtobject.authProceed()
            } else {
                var dialog = app.pinDialog.createObject(app, {mode: 'check', pincode: Config.pinCode})
                dialog.accepted.connect(function() {
                    qtobject.authProceed()
                    dialog.close()
                })
                dialog.rejected.connect(function() {
                    qtobject.authCancel()
                })
                dialog.open()
            }
        } else {
            console.log('unknown auth method ' + method)
            qtobject.authCancel()
        }
    }

    property var _lastActive: 0 // record time of last activity
    property int _maxInactive: 30 // seconds
    property bool _lockDialogShown: false

    onActiveChanged: {
        if (!active) {
            // deactivated
            _lastActive = Date.now()
        } else {
            // activated
            if (_lastActive != 0 && Date.now() - _lastActive > _maxInactive * 1000) {
                if (_lockDialogShown || Config.pinCode == '')
                    return
                var dialog = app.pinDialog.createObject(app, {mode: 'check', canCancel: false, pincode: Config.pinCode})
                dialog.accepted.connect(function() {
                    dialog.close()
                    _lockDialogShown = false
                })
                dialog.open()
                _lockDialogShown = true
            }
        }
    }

}
