import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0
import QtQuick.Controls.Material.impl 2.12
import QtQuick.Window 2.15

import QtQml 2.6
import QtMultimedia 5.6

import org.electrum 1.0

import "controls"

ApplicationWindow
{
    id: app

    visible: false // initial value

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

    property bool _wantClose: false
    property var _exceptionDialog

    property QtObject appMenu: Menu {
        parent: Overlay.overlay
        dim: true
        modal: true
        Overlay.modal: Rectangle {
            color: "#44000000"
        }

        id: menu

        MenuItem {
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/network.png'
            action: Action {
                text: qsTr('Network')
                onTriggered: menu.openPage(Qt.resolvedUrl('NetworkOverview.qml'))
                enabled: stack.currentItem.objectName != 'NetworkOverview'
            }
        }

        MenuItem {
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/preferences.png'
            action: Action {
                text: qsTr('Preferences')
                onTriggered: menu.openPage(Qt.resolvedUrl('Preferences.qml'))
                enabled: stack.currentItem.objectName != 'Properties'
            }
        }

        MenuItem {
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/electrum.png'
            action: Action {
                text: qsTr('About');
                onTriggered: menu.openPage(Qt.resolvedUrl('About.qml'))
                enabled: stack.currentItem.objectName != 'About'
            }
        }

        function openPage(url) {
            stack.pushOnRoot(url)
            currentIndex = -1
        }
    }

    function openAppMenu() {
        appMenu.open()
        appMenu.x = app.width - appMenu.width
        appMenu.y = toolbar.height
    }

    header: ToolBar {
        id: toolbar

        background: Rectangle {
            implicitHeight: 48
            color: Material.dialogColor

            layer.enabled: true
            layer.effect: ElevationEffect {
                elevation: 4
                fullWidth: true
            }
        }

        ColumnLayout {
            spacing: 0
            width: parent.width
            height: toolbar.height

            RowLayout {
                id: toolbarTopLayout

                Layout.fillWidth: true
                Layout.rightMargin: constants.paddingMedium
                Layout.alignment: Qt.AlignVCenter

                Item {
                    Layout.fillWidth: true
                    Layout.preferredHeight: Math.max(implicitHeight, toolbarTopLayout.height)

                    MouseArea {
                        anchors.fill: parent
                        enabled: Daemon.currentWallet && (!stack.currentItem.title || stack.currentItem.title == Daemon.currentWallet.name)
                        onClicked: {
                            stack.getRoot().menu.open()  // open wallet-menu
                            stack.getRoot().menu.y = toolbar.height
                        }
                    }

                    RowLayout {
                        width: parent.width

                        Item {
                            Layout.preferredWidth: constants.paddingXLarge
                            Layout.preferredHeight: 1
                        }

                        Image {
                            Layout.preferredWidth: constants.iconSizeSmall
                            Layout.preferredHeight: constants.iconSizeSmall
                            visible: Daemon.currentWallet && (!stack.currentItem.title || stack.currentItem.title == Daemon.currentWallet.name)
                            source: '../../icons/wallet.png'
                        }

                        Label {
                            Layout.fillWidth: true
                            Layout.preferredHeight: Math.max(implicitHeight, toolbarTopLayout.height)
                            text: stack.currentItem.title
                                ? stack.currentItem.title
                                : Daemon.currentWallet.name
                            elide: Label.ElideRight
                            verticalAlignment: Qt.AlignVCenter
                            font.pixelSize: constants.fontSizeMedium
                            font.bold: true
                        }
                    }
                }

                Item {
                    implicitHeight: 48
                    implicitWidth: statusIconsLayout.width

                    MouseArea {
                        anchors.fill: parent
                        onClicked: openAppMenu()  // open global-app-menu
                    }

                    RowLayout {
                        id: statusIconsLayout
                        anchors.verticalCenter: parent.verticalCenter

                        Item {
                            Layout.preferredWidth: constants.paddingLarge
                            Layout.preferredHeight: 1
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

                        LightningNetworkStatusIndicator {}
                        OnchainNetworkStatusIndicator {}
                    }
                }
            }

            WalletSummary {
                id: walletSummary
                Layout.preferredWidth: app.width
            }
        }
    }

    StackView {
        id: mainStackView
        width: parent.width
        height: keyboardFreeZone.height - header.height
        initialItem: Qt.resolvedUrl('WalletMainView.qml')

        function getRoot() {
            return mainStackView.get(0)
        }
        function pushOnRoot(item) {
            if (mainStackView.depth > 1) {
                mainStackView.replace(mainStackView.get(1), item)
            } else {
                mainStackView.push(item)
            }
        }
    }

    Timer {
        id: coverTimer
        interval: 10
        onTriggered: {
            app.visible = true
            cover.opacity = 0
        }
    }

    Rectangle {
        id: cover
        parent: Overlay.overlay
        anchors.fill: parent

        z: 1000
        color: 'black'

        Behavior on opacity {
            enabled: AppController ? AppController.isAndroid() : false
            NumberAnimation {
                duration: 1000
                easing.type: Easing.OutQuad;
            }
        }
    }

    Item {
        id: keyboardFreeZone
        // Item as first child in Overlay that adjusts its size to the available
        // screen space minus the virtual keyboard (e.g. to center dialogs in)
        // see also ElDialog.resizeWithKeyboard property
        parent: Overlay.overlay
        width: parent.width
        height: parent.height

        states: State {
            name: "visible"
            when: Qt.inputMethod.visible
            PropertyChanges {
                target: keyboardFreeZone
                height: keyboardFreeZone.parent.height - Qt.inputMethod.keyboardRectangle.height / Screen.devicePixelRatio
            }
        }
        transitions: [
            Transition {
                from: ''
                to: 'visible'
                ParallelAnimation {
                    NumberAnimation {
                        properties: "height"
                        duration: 250
                        easing.type: Easing.OutQuad
                    }
                }
            },
            Transition {
                from: 'visible'
                to: ''
                ParallelAnimation {
                    NumberAnimation {
                        properties: "height"
                        duration: 50
                        easing.type: Easing.OutQuad
                    }
                }
            }
        ]

    }

    property alias newWalletWizard: _newWalletWizard
    Component {
        id: _newWalletWizard
        NewWalletWizard {
            onClosed: destroy()
        }
    }

    property alias serverConnectWizard: _serverConnectWizard
    Component {
        id: _serverConnectWizard
        ServerConnectWizard {
            onClosed: destroy()
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

    property alias loadingWalletDialog: _loadingWalletDialog
    Component {
        id: _loadingWalletDialog
        LoadingWalletDialog {
            onClosed: destroy()
        }
    }

    property alias scanDialog: _scanDialog
    Component {
        id: _scanDialog
        ScanDialog {
            onClosed: destroy()
        }
    }

    property alias channelOpenProgressDialog: _channelOpenProgressDialog
    ChannelOpenProgressDialog {
        id: _channelOpenProgressDialog
    }

    Component {
        id: swapDialog
        SwapDialog {
            onClosed: destroy()
            swaphelper: SwapHelper {
                id: _swaphelper
                wallet: Daemon.currentWallet
                onAuthRequired: {
                    app.handleAuthRequired(_swaphelper, method, authMessage)
                }
                onError: {
                    var dialog = app.messageDialog.createObject(app, { title: qsTr('Error'), text: message })
                    dialog.open()
                }
            }
        }
    }

    NotificationPopup {
        id: notificationPopup
        width: parent.width
    }

    Component {
        id: crashDialog
        ExceptionDialog {
            z: 1000
        }
    }

    Component.onCompleted: {
        coverTimer.start()

        if (!Config.autoConnectDefined) {
            var dialog = serverConnectWizard.createObject(app)
            // without completed serverConnectWizard we can't start
            dialog.rejected.connect(function() {
                app.visible = false
                Qt.callLater(Qt.quit)
            })
            dialog.accepted.connect(function() {
                Daemon.startNetwork()
                var newww = app.newWalletWizard.createObject(app)
                newww.walletCreated.connect(function() {
                    Daemon.availableWallets.reload()
                    // and load the new wallet
                    Daemon.loadWallet(newww.path, newww.wizard_data['password'])
                })
                newww.open()
            })
            dialog.open()
        } else {
            Daemon.startNetwork()
            if (Daemon.availableWallets.rowCount() > 0) {
                Daemon.loadWallet()
            } else {
                var newww = app.newWalletWizard.createObject(app)
                newww.walletCreated.connect(function() {
                    Daemon.availableWallets.reload()
                    // and load the new wallet
                    Daemon.loadWallet(newww.path, newww.wizard_data['password'])
                })
                newww.open()
            }
        }
    }

    onClosing: {
        if (activeDialogs.length > 0) {
            var activeDialog = activeDialogs[activeDialogs.length - 1]
            if (activeDialog.allowClose) {
                activeDialog.doClose()
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
            if (app._wantClose) {
                app.header.visible = false
                mainStackView.clear()
            } else {
                var dialog = app.messageDialog.createObject(app, {
                    title: qsTr('Close Electrum?'),
                    yesno: true
                })
                dialog.accepted.connect(function() {
                    app._wantClose = true
                    app.close()
                })
                dialog.open()
                close.accepted = false
            }
        }
    }

    Connections {
        target: Daemon
        function onWalletRequiresPassword(name, path) {
            console.log('wallet requires password')
            var dialog = openWalletDialog.createObject(app, { path: path, name: name })
            dialog.open()
        }
        function onWalletOpenError(error) {
            console.log('wallet open error')
            var dialog = app.messageDialog.createObject(app, { title: qsTr('Error'), 'text': error })
            dialog.open()
        }
        function onAuthRequired(method, authMessage) {
            handleAuthRequired(Daemon, method, authMessage)
        }
        function onLoadingChanged() {
            if (!Daemon.loading)
                return
            console.log('wallet loading')
            var dialog = loadingWalletDialog.createObject(app, { allowClose: false } )
            dialog.open()
        }
    }

    Connections {
        target: AppController
        function onUserNotify(wallet_name, message) {
            notificationPopup.show(wallet_name, message)
        }
        function onShowException(crash_data) {
            if (app._exceptionDialog)
                return
            app._exceptionDialog = crashDialog.createObject(app, {
                crashData: crash_data
            })
            app._exceptionDialog.onClosed.connect(function() {
                app._exceptionDialog = null
            })
            app._exceptionDialog.open()
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onAuthRequired(method, authMessage) {
            handleAuthRequired(Daemon.currentWallet, method, authMessage)
        }
        // TODO: add to notification queue instead of barging through
        function onPaymentSucceeded(key) {
            notificationPopup.show(Daemon.currentWallet.name, qsTr('Payment Succeeded'))
        }
        function onPaymentFailed(key, reason) {
            notificationPopup.show(Daemon.currentWallet.name, qsTr('Payment Failed') + ': ' + reason)
        }
    }

    Connections {
        target: Config
        function onAuthRequired(method, authMessage) {
            handleAuthRequired(Config, method, authMessage)
        }
    }

    // handle auth_protect decorator events. These MUST
    // (eventually) end with a call to qtobject.authProceed()
    // or qtobject.authCancel().
    //
    // The following method types are defined:
    //
    // 'wallet_password': User must supply a password
    // that matches the storage password (if set)
    // or the keystore password. This forces password
    // verification in all cases, even for wallets using
    // keystore-only passwords (unless the storage and
    // keystore are both unencrypted).
    // It's primary use is password knowledge verification
    // before presenting a secret (e.g. seed) or doing
    // something irreversible (e.g. delete wallet)
    //
    // 'keystore': User must supply a password
    // that matches the keystore password (if set).
    //
    // 'keystore_else_pin': User must supply a password
    // that matches the keystore password (if set), unless
    // the keystore is 'unlocked' which means the wallet password
    // has been given when opening the wallet, and is the same as
    // the keystore password (should always be the case). In that
    // case a PIN is asked.
    // This is mainly used when signing a transaction.
    //
    // 'pin': User must supply the configured PIN code
    //

    function handleAuthRequired(qtobject, method, authMessage) {
        console.log('auth using method ' + method)
        if (method == 'wallet_password') {
            if (!Daemon.currentWallet.isEncrypted
                    && Daemon.currentWallet.verifyKeystorePassword('')) {
                // wallet has no password
                qtobject.authProceed()
            } else {
                if (!Daemon.currentWallet.isEncrypted) {
                    handleAuthVerifyPassword(qtobject, authMessage, function(password) {
                        return Daemon.currentWallet.verifyKeystorePassword(password)
                    })
                } else {
                    handleAuthVerifyPassword(qtobject, authMessage, function(password) {
                        return Daemon.currentWallet.verifyPassword(password)
                    })
                }
            }
        } else if (method == 'keystore_else_pin') {
            if (!Daemon.currentWallet.canHaveKeystoreEncryption()
                    || Daemon.currentWallet.verifyKeystorePassword('')) {
                handleAuthRequired(qtobject, 'pin', authMessage)
            } else if (Daemon.currentWallet.isKeystorePasswordWalletPassword()) {
                handleAuthRequired(qtobject, 'pin', authMessage)
            } else {
                handleAuthVerifyPassword(qtobject, authMessage, function(password) {
                    return Daemon.currentWallet.verifyKeystorePassword(password)
                })
            }
        } else if (method == 'keystore') {
            if (!Daemon.currentWallet.canHaveKeystoreEncryption()
                    || Daemon.currentWallet.verifyKeystorePassword('')) {
                qtobject.authProceed()
            } else {
                handleAuthVerifyPassword(qtobject, authMessage, function(password) {
                    return Daemon.currentWallet.verifyKeystorePassword(password)
                })
            }
        } else if (method == 'pin') {
            if (Config.pinCode == '') {
                // no PIN configured
                handleAuthConfirmationOnly(qtobject, authMessage)
            } else {
                handleAuthVerifyPin(qtobject, authMessage)
            }
        } else {
            console.log('unknown auth method ' + method)
            qtobject.authCancel()
        }
    }

    function handleAuthVerifyPassword(qtobject, authMessage, validator) {
        var dialog = app.passwordDialog.createObject(app, {
            title: authMessage ? authMessage : qsTr('Enter current password')
        })
        dialog.accepted.connect(function() {
            if (validator(dialog.password)) {
                qtobject.authProceed(dialog.password)
            } else {
                qtobject.authCancel()
                var fdialog = app.messageDialog.createObject(app, {
                    title: qsTr('Password incorrect')
                })
                fdialog.open()
            }
        })
        dialog.rejected.connect(function() {
            qtobject.authCancel()
        })
        dialog.open()
    }

    function handleAuthConfirmationOnly(qtobject, authMessage) {
        if (!authMessage) {
            qtobject.authProceed()
            return
        }
        var dialog = app.messageDialog.createObject(app, {title: authMessage, yesno: true})
        dialog.accepted.connect(function() {
            qtobject.authProceed()
        })
        dialog.rejected.connect(function() {
            qtobject.authCancel()
        })
        dialog.open()
    }

    function handleAuthVerifyPin(qtobject, authMessage) {
        var dialog = app.pinDialog.createObject(app, {
            mode: 'check',
            pincode: Config.pinCode,
            authMessage: authMessage
        })
        dialog.accepted.connect(function() {
            qtobject.authProceed()
            dialog.close()
        })
        dialog.rejected.connect(function() {
            qtobject.authCancel()
        })
        dialog.open()
    }

    function startSwap() {
        var swapdialog = swapDialog.createObject(app)
        swapdialog.open()
    }

    property var _lastActive: 0 // record time of last activity
    property bool _lockDialogShown: false

}
