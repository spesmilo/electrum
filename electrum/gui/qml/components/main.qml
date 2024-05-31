import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Basic
import QtQuick.Controls.Material
import QtQuick.Controls.Material.impl
import QtQuick.Window

import QtQml
import QtMultimedia

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

    property QtObject constants: appconstants
    Constants { id: appconstants }

    property alias stack: mainStackView
    property alias keyboardFreeZone: _keyboardFreeZone

    property variant activeDialogs: []

    property var _exceptionDialog

    property QtObject appMenu: Menu {
        id: menu

        parent: Overlay.overlay
        dim: true
        modal: true
        Overlay.modal: Rectangle {
            color: "#44000000"
        }

        property int implicitChildrenWidth: 64
        width: implicitChildrenWidth + 60 + constants.paddingLarge

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

        // determine widest element and store in implicitChildrenWidth
        function updateImplicitWidth() {
            for (let i = 0; i < menu.count; i++) {
                var item = menu.itemAt(i)
                var txt = item.text
                var txtwidth = fontMetrics.advanceWidth(txt)
                if (txtwidth > menu.implicitChildrenWidth) {
                    menu.implicitChildrenWidth = txtwidth
                }
            }
        }

        FontMetrics {
            id: fontMetrics
            font: menu.font
        }

        Component.onCompleted: updateImplicitWidth()
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
            anchors.left: parent.left
            anchors.right: parent.right
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
                        enabled: Daemon.currentWallet &&
                            (!stack.currentItem || !stack.currentItem.title || stack.currentItem.title == Daemon.currentWallet.name)
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
                            visible: Daemon.currentWallet &&
                                (!stack.currentItem || !stack.currentItem.title || stack.currentItem.title == Daemon.currentWallet.name)
                            source: '../../icons/wallet.png'
                        }

                        Label {
                            Layout.fillWidth: true
                            Layout.preferredHeight: Math.max(implicitHeight, toolbarTopLayout.height)
                            text: stack.currentItem && stack.currentItem.title
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

                        LightningNetworkStatusIndicator {
                            id: lnnsi
                        }
                        OnchainNetworkStatusIndicator { }
                    }
                }
            }

            // hack to force relayout of toolbar
            // since qt6 LightningNetworkStatusIndicator.visible doesn't trigger relayout(?)
            Item {
                Layout.preferredHeight: 1
                Layout.topMargin: -1
                Layout.preferredWidth: lnnsi.visible
                    ? 1
                    : 2
            }
        }
    }

    StackView {
        id: mainStackView
        width: parent.width
        height: _keyboardFreeZone.height - header.height
        initialItem: Component {
            WalletMainView {}
        }

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
        id: _keyboardFreeZone
        // Item as first child in Overlay that adjusts its size to the available
        // screen space minus the virtual keyboard (e.g. to center dialogs in)
        // see also ElDialog.resizeWithKeyboard property
        parent: Overlay.overlay
        width: parent.width
        height: parent.height

        states: [
            State {
                name: 'visible'
                when: Qt.inputMethod.keyboardRectangle.y
                PropertyChanges {
                    target: _keyboardFreeZone
                    height: _keyboardFreeZone.parent.height - (Screen.desktopAvailableHeight - (Qt.inputMethod.keyboardRectangle.y/Screen.devicePixelRatio))
                }
            }
        ]

        transitions: [
            Transition {
                from: ''
                to: 'visible'
                NumberAnimation {
                    properties: 'height'
                    duration: 100
                    easing.type: Easing.OutQuad
                }
            },
            Transition {
                from: 'visible'
                to: ''
                SequentialAnimation {
                    PauseAnimation {
                        duration: 200
                    }
                    NumberAnimation {
                        properties: 'height'
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

    property alias helpDialog: _helpDialog
    Component {
        id: _helpDialog
        HelpDialog {
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

    property Component scanDialog  // set in Component.onCompleted
    Component {
        id: _scanDialog
        QRScanner {
            onFinished: destroy()
        }
    }
    Component {
        id: _qtScanDialog
        ScanDialog {
            onClosed: destroy()
        }
    }

    property alias channelOpenProgressDialog: _channelOpenProgressDialog
    ChannelOpenProgressDialog {
        id: _channelOpenProgressDialog
    }

    property alias signVerifyMessageDialog: _signVerifyMessageDialog
    Component {
        id: _signVerifyMessageDialog
        SignVerifyMessageDialog {
            onClosed: destroy()
        }
    }

    Component {
        id: swapDialog
        SwapDialog {
            onClosed: destroy()
            swaphelper: SwapHelper {
                id: _swaphelper
                wallet: Daemon.currentWallet
                onAuthRequired: (method, authMessage) => {
                    app.handleAuthRequired(_swaphelper, method, authMessage)
                }
                onError: (message) => {
                    var dialog = app.messageDialog.createObject(app, {
                        title: qsTr('Error'),
                        iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                        text: message
                    })
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

        if (AppController.isAndroid()) {
            app.scanDialog = _scanDialog
        } else {
            app.scanDialog = _qtScanDialog
        }

        if (!Config.autoConnectDefined) {
            var dialog = serverConnectWizard.createObject(app)
            // without completed serverConnectWizard we can't start
            dialog.rejected.connect(function() {
                app.visible = false
                AppController.wantClose = true
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

    onClosing: (close) => {
        if (AppController.wantClose) {
            // destroy most GUI components so that we don't dump so many null reference warnings on exit
            app.header.visible = false
            mainStackView.clear()
            return
        }
        if (activeDialogs.length > 0) {
            var activeDialog = activeDialogs[activeDialogs.length - 1]
            if (activeDialog.allowClose) {
                console.log('main: dialog.doClose')
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
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Close Electrum?'),
                yesno: true
            })
            dialog.accepted.connect(function() {
                AppController.wantClose = true
                app.close()
            })
            dialog.open()
            close.accepted = false
        }
    }

    property var _opendialog: undefined

    function showOpenWalletDialog(name, path) {
        if (_opendialog == undefined) {
            _opendialog = openWalletDialog.createObject(app, { name: name, path: path })
            _opendialog.closed.connect(function() {
                _opendialog = undefined
            })
            _opendialog.open()
        }
    }

    Connections {
        target: Daemon
        function onWalletRequiresPassword(name, path) {
            console.log('wallet requires password')
            showOpenWalletDialog(name, path)
        }
        function onWalletOpenError(error) {
            console.log('wallet open error')
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: error
            })
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

    function handleAuthRequired(qtobject, method, authMessage) {
        console.log('auth using method ' + method)

        if (method == 'wallet_else_pin') {
            // if there is a loaded wallet and all wallets use the same password, use that
            // else delegate to pin auth
            if (Daemon.currentWallet && Daemon.singlePasswordEnabled) {
                method = 'wallet'
            } else {
                method = 'pin'
            }
        }

        if (method == 'wallet') {
            if (Daemon.currentWallet.verifyPassword('')) {
                // wallet has no password
                qtobject.authProceed()
            } else {
                var dialog = app.passwordDialog.createObject(app, {'title': qsTr('Enter current password')})
                dialog.accepted.connect(function() {
                    if (Daemon.currentWallet.verifyPassword(dialog.password)) {
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
                handleAuthConfirmationOnly(qtobject, authMessage)
            } else {
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
        } else {
            console.log('unknown auth method ' + method)
            qtobject.authCancel()
        }
    }

    function handleAuthConfirmationOnly(qtobject, authMessage) {
        if (!authMessage) {
            qtobject.authProceed()
            return
        }
        var dialog = app.messageDialog.createObject(app, {
            title: authMessage,
            yesno: true
        })
        dialog.accepted.connect(function() {
            qtobject.authProceed()
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
