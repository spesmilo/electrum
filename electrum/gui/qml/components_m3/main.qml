import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Basic
import QtQuick.Controls.Material
import QtQuick.Window

import QtQml

import org.electrum 1.0

import "../components" as Classic
import "../components/controls" as CC
import "controls"

// Window of the Material 3 GUI (qml_ui_style = 'material3'), loaded instead of components/main.qml.
// Everything non-visual is carried over verbatim from components/main.qml @ 4f36c4489: the `app`
// contract the classic screens rely on (stack, keyboardFreeZone, infobanner, dialog factories,
// activeDialogs, ...), the handlers of Daemon / Biometrics / AppController / Config, authentication,
// startup and onClosing. Differences from the original are marked with `// M3:`.
// The window keeps the classic dark theme, so every classic page, dialog and menu looks as today;
// Material 3 pages and popups set their own (light or dark) theme from `m3` (M3Theme.qml).
ApplicationWindow
{
    id: app

    visible: false // initial value

    readonly property int statusBarHeight: AppController ? AppController.getStatusBarHeight() : 0
    readonly property int navigationBarHeight: AppController ? AppController.getNavigationBarHeight() : 0

    // dimensions ignored on android
    width: 480
    height: 800

    Material.theme: Material.Dark
    Material.primary: Material.Indigo
    Material.accent: Material.LightBlue
    font.pixelSize: constants.fontSizeMedium

    property QtObject constants: appconstants
    Classic.Constants { id: appconstants }

    // M3: Material 3 theme (color roles, type scale, shapes); separate from the classic `constants`
    property QtObject m3: m3theme
    M3Theme { id: m3theme }

    // M3: routes, one URL per page that Material 3 code opens (M3Routes.qml); open them with pushPage/loadPage
    property QtObject routes: m3routes
    M3Routes { id: m3routes }

    // M3: the ready component of the page at `url`; when it cannot be loaded, the classic page of the route
    // (routes.classicFor), else null; the error goes to the log. The stack only gets ready components: a push
    // of a page that fails to load leaves StackView broken (see PaymentFlow._loadPage).
    function loadPage(url) {
        var component = Qt.createComponent(url)
        if (component.status === Component.Ready)
            return component
        console.log('M3: cannot load ' + url + ': ' + component.errorString())
        var classic = routes.classicFor(url)
        if (classic == '' || String(classic) === String(url))
            return null
        console.log('M3: opening the classic page ' + classic + ' instead')
        component = Qt.createComponent(classic)
        if (component.status === Component.Ready)
            return component
        console.log('M3: cannot load ' + classic + ': ' + component.errorString())
        return null
    }

    // M3: URL to open for the route `url`: the route itself, or its classic page when the route cannot be
    // loaded (for callers that load the page themselves, PaymentFlow._showPage)
    function pageUrl(url) {
        var component = loadPage(url)
        return component ? component.url : url
    }

    // M3: pushes the page at `url` (a route) with `properties`; returns the page, or null when no page
    // could be loaded (the stack is then unchanged)
    function pushPage(url, properties) {
        var component = loadPage(url)
        if (!component)
            return null
        return mainStackView.push(component, properties ? properties : {})
    }

    // M3: as pushPage, in place of the page above the root (stack.pushOnRoot: pages opened from the overflow
    // menu, the tabs and the chips replace each other instead of piling up)
    function pushPageOnRoot(url) {
        var component = loadPage(url)
        if (!component)
            return null
        mainStackView.pushOnRoot(component)
        return mainStackView.currentItem
    }

    property alias stack: mainStackView
    property alias keyboardFreeZone: _keyboardFreeZone
    property alias infobanner: _infobanner
    property color _navigationBarBackgroundColor: 'transparent'

    property string pendingIntent: ""

    property variant activeDialogs: []

    property var _exceptionDialog

    property var pluginobjects: ({})

    // M3: the classic appMenu and wallet menu are replaced by one overflow menu (the overflow button of the top
    // app bar); nothing outside main.qml calls appMenu/openAppMenu.
    readonly property bool _m3WalletRoot: mainStackView.depth > 0 && mainStackView.get(0)
        && mainStackView.get(0).m3WalletRoot === true
        && Daemon.currentWallet != null

    // M3: items taken from the classic menus keep the translation context of their classic file
    // (qsTr takes it from the file name).
    M3Menu {
        id: m3Menu

        // bindings: the menu sets its width from its items when it opens
        x: app.width - m3Menu.width - m3.space8
        y: toolbar.height - m3.space8

        function openPage(url) {
            app.pushPageOnRoot(url)  // M3: a route (app.routes)
        }

        MenuItem {
            text: qsTranslate('Wallets', 'Wallets')
            // as "Other wallets" in the classic wallet menu: not on the Wallets page itself
            enabled: !(mainStackView.currentItem && mainStackView.currentItem.objectName === 'Wallets')
            onTriggered: m3Menu.openPage(app.routes.wallets)
        }
        MenuItem {
            text: qsTranslate('WalletMainView', 'Wallet details')
            enabled: app._m3WalletRoot
            onTriggered: m3Menu.openPage(app.routes.walletDetails)
        }
        MenuItem {
            text: qsTranslate('WalletMainView', 'Addresses/Coins')
            enabled: app._m3WalletRoot
            onTriggered: m3Menu.openPage(app.routes.addresses)
        }
        MenuItem {
            text: qsTr('Invoices')
            enabled: app._m3WalletRoot
            onTriggered: m3Menu.openPage(app.routes.invoices)
        }
        MenuItem {
            text: qsTr('Requests')
            enabled: app._m3WalletRoot
            onTriggered: {
                Daemon.currentWallet.deleteExpiredRequests()
                m3Menu.openPage(app.routes.receiveRequests)
            }
        }
        MenuItem {
            text: app._m3WalletRoot && !Daemon.currentWallet.canSignMessage
                ? qsTranslate('WalletMainView', 'Verify Message')
                : qsTranslate('WalletMainView', 'Sign/Verify Message')
            enabled: app._m3WalletRoot
            onTriggered: {
                var dialog = app.signVerifyMessageDialog.createObject(app)
                dialog.open()
            }
        }
        MenuItem {
            text: qsTranslate('WalletMainView', 'Sweep key(s)')
            enabled: app._m3WalletRoot
            onTriggered: mainStackView.get(0).startSweep()
        }
        MenuSeparator {}
        MenuItem {
            text: qsTr('Network')
            onTriggered: m3Menu.openPage(app.routes.networkOverview)
        }
        MenuItem {
            // until the Material 3 settings screen replaces it (Settings tab)
            text: qsTr('Preferences')
            onTriggered: m3Menu.openPage(app.routes.preferences)
        }
        MenuItem {
            text: qsTr('About')
            onTriggered: m3Menu.openPage(app.routes.about)
        }
        MenuSeparator {}
        MenuItem {
            // way back to the classic GUI, also when a Material 3 screen is broken
            text: qsTr('Classic interface...')
            onTriggered: app.showRestartDialog()
        }
    }

    function openM3Menu() {
        m3Menu.open()
    }

    // Way back to the classic GUI (overflow menu, Settings tab). The setting is written only by
    // "Close Electrum" and "On next start"; "Cancel" changes nothing.
    function showRestartDialog() {
        var dialog = _restartDialog.createObject(app)
        dialog.open()
        return dialog
    }

    Component {
        id: _restartDialog
        M3Dialog {
            id: restartDialog

            title: qsTr('Classic interface')
            text: qsTr('Switch to the classic interface? It will be activated after restarting Electrum.')

            function choose(close_app) {
                Config.uiStyle = 'classic'
                restartDialog.doAccept()
                if (close_app) {
                    // same path as the confirmation of "Close Electrum?" in onClosing
                    AppController.wantClose = true
                    app.close()
                }
            }

            buttons: [
                M3Button {
                    variant: 'text'
                    text: qsTr('Close Electrum')
                    onClicked: restartDialog.choose(true)
                },
                M3Button {
                    variant: 'text'
                    text: qsTr('On next start')
                    onClicked: restartDialog.choose(false)
                },
                M3Button {
                    variant: 'text'
                    text: qsTr('Cancel')
                    onClicked: restartDialog.doReject()
                }
            ]

            onClosed: destroy()
        }
    }

    // M3: Material 3 top app bar for every page (Material 3 or classic): back arrow on pushed
    // pages, title of the current page (or the wallet name, as the classic header), overflow menu
    // on the root of the stack.
    header: M3TopAppBar {
        id: toolbar

        readonly property var page: mainStackView.currentItem

        showBack: mainStackView.depth > 1
        title: page && page.title
            ? page.title
            : Daemon.currentWallet ? Daemon.currentWallet.name : ''
        subtitle: page && 'subtitle' in page && page.subtitle ? page.subtitle : ''
        // M3: actions of the current page (M2-MAP F-3): icon buttons the page lists in its `m3Actions`
        actions: page && page.m3Actions ? page.m3Actions : []
        showOverflow: mainStackView.depth <= 1 && !(page && page.hideOverflow === true)

        onBackClicked: mainStackView.pop()
        onOverflowClicked: app.openM3Menu()
    }

    ColumnLayout {
        width: parent.width
        height: _keyboardFreeZone.height - header.height
        spacing: 0

        // M3: Material 3 banner with the API of the classic InfoBanner
        M3Banner {
            id: _infobanner
            Layout.fillWidth: true
        }

        StackView {
            id: mainStackView
            Layout.fillHeight: true
            Layout.fillWidth: true

            initialItem: Component {
                Classic.Wallets {}
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
            // M3: classic screens pass bare file names (Wallets.qml: 'WalletMainView.qml',
            // WalletMainView: 'Wallets.qml'); they resolve relative to components_m3/, except the
            // classic pages listed here, which have no Material 3 counterpart yet.
            readonly property var _classicRoots: ({
                'Wallets.qml': '../components/Wallets.qml'
            })
            function replaceRoot(item_url) {
                mainStackView.clear()
                mainStackView.push(Qt.resolvedUrl(item_url in _classicRoots ? _classicRoots[item_url] : item_url))
            }
            // M3: the strip below (one owner of navigationBarHeight; Material 3 pages do not pad for
            // it themselves) takes the color of the page on top, as a live binding (theme switch).
            // A classic page draws its own dark color while the Material 3 theme is dark; in the
            // light theme the system navigation bar icons are dark (styleHints.colorScheme, see
            // M3Theme), so the strip is light too, or the back/home buttons would vanish.
            function updateStylingFromItem(item) {
                _navigationBarBackgroundColor = Qt.binding(function() {
                    if (item && item.m3Page === true)
                        return item.navigationBarBackgroundColor
                    if (!m3.dark)
                        return m3.surfaceContainer
                    return item && 'navigationBarBackgroundColor' in item
                        ? item.navigationBarBackgroundColor
                        : 'transparent'
                })
            }
            onCurrentItemChanged: updateStylingFromItem(currentItem)
        }

        // Add bottom padding for navigation bar on Android when UI is edge-to-edge
        Item {
            visible: app.navigationBarHeight > 0 && _keyboardFreeZone.state != 'visible'
            Layout.fillWidth: true
            Layout.preferredHeight: app.navigationBarHeight

            Rectangle { anchors.fill: parent; color: _navigationBarBackgroundColor }
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
        Classic.NewWalletWizard {
            onClosed: destroy()
        }
    }

    property alias termsOfUseWizard: _termsOfUseWizard
    Component {
        id: _termsOfUseWizard
        Classic.TermsOfUseWizard {
            onClosed: destroy()
        }
    }

    property alias serverConnectWizard: _serverConnectWizard
    Component {
        id: _serverConnectWizard
        Classic.ServerConnectWizard {
            onClosed: destroy()
        }
    }

    property alias messageDialog: _messageDialog
    Component {
        id: _messageDialog
        Classic.MessageDialog {
            onClosed: destroy()
        }
    }

    property alias helpDialog: _helpDialog
    Component {
        id: _helpDialog
        CC.HelpDialog {
            onClosed: destroy()
        }
    }

    property alias passwordDialog: _passwordDialog
    Component {
        id: _passwordDialog
        Classic.PasswordDialog {
            onClosed: destroy()
        }
    }

    property alias genericShareDialog: _genericShareDialog
    Component {
        id: _genericShareDialog
        Classic.GenericShareDialog {
            onClosed: destroy()
        }
    }

    property alias openWalletDialog: _openWalletDialog
    Component {
        id: _openWalletDialog
        Classic.OpenWalletDialog {
            onClosed: destroy()
        }
    }

    property alias loadingWalletDialog: _loadingWalletDialog
    Component {
        id: _loadingWalletDialog
        Classic.LoadingWalletDialog {
            onClosed: destroy()
        }
    }

    property alias scanDialog: _scanDialog
    Component {
        id: _scanDialog
        Classic.ScanDialog {}
    }

    Component {
        id: crashDialog
        Classic.ExceptionDialog {
            onClosed: destroy()
        }
    }

    property alias channelOpenProgressDialog: _channelOpenProgressDialog
    Classic.ChannelOpenProgressDialog {
        id: _channelOpenProgressDialog
    }

    // M3: one factory for "Open channel" (Channels and BalanceDetails, M2-MAP F-12); the channels group
    // replaces the type by the Material 3 dialog
    property alias openChannelDialog: _openChannelDialog
    Component {
        id: _openChannelDialog
        Classic.OpenChannelDialog {
            onClosed: destroy()
        }
    }

    property alias signVerifyMessageDialog: _signVerifyMessageDialog
    Component {
        id: _signVerifyMessageDialog
        Classic.SignVerifyMessageDialog {
            onClosed: destroy()
        }
    }

    property alias nostrSwapServersDialog: _nostrSwapServersDialog
    Component {
        id: _nostrSwapServersDialog
        Classic.NostrSwapServersDialog {
            onClosed: destroy()
        }
    }

    Component {
        id: swapDialog
        Classic.SwapDialog {
            id: _swapdialog
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
                onUndefinedNPub: {
                    var dialog = app.nostrSwapServersDialog.createObject(app, {
                        swaphelper: _swaphelper,
                        selectedPubkey: Config.swapServerNPub
                    })
                    dialog.accepted.connect(function() {
                        Config.swapServerNPub = dialog.selectedPubkey
                        _swaphelper.setReadyState()
                    })
                    dialog.rejected.connect(function() {
                        _swaphelper.npubSelectionCancelled()
                    })
                    dialog.open()
                }
            }
        }
    }

    Classic.NotificationPopup {
        id: notificationPopup
        width: parent.width
    }

    Component.onCompleted: {
        coverTimer.start()

        function continueWithServerConnection() {
            if (!Network.autoConnectDefined) {
                var dialog = serverConnectWizard.createObject(app)
                // without completed serverConnectWizard we can't start
                dialog.rejected.connect(function() {
                    app.quitApp()
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

        if (!Config.termsOfUseAccepted) {
            var dialog = termsOfUseWizard.createObject(app)

            dialog.rejected.connect(function() {
                app.quitApp()
            })
            dialog.accepted.connect(function() {
                Config.termsOfUseAccepted = true
                continueWithServerConnection()
            })
            dialog.open()
        } else {
            continueWithServerConnection()
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
        } else if (stack.currentItem && stack.currentItem.handleBack && stack.currentItem.handleBack()) {
            // M3: the root page may take the back button (another tab -> Wallet tab)
            close.accepted = false
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

    function quitApp() {
        // quit the app immediately
        app.visible = false
        AppController.wantClose = true
        Qt.callLater(Qt.quit)
    }

    property var _pendingBiometricAuth: null
    property var _loadingWalletContext: null

    Connections {
        target: Biometrics
        function onUnlockSuccess(password) {
            if (app._pendingBiometricAuth) {
                if (app._pendingBiometricAuth.action === 'load_wallet') {
                    app._loadingWalletContext = _pendingBiometricAuth
                    Daemon.loadWallet(app._pendingBiometricAuth.path, password)
                    app._pendingBiometricAuth = null
                    return
                }

                let qtobject = app._pendingBiometricAuth.qtobject
                let method = app._pendingBiometricAuth.method

                if (Daemon.currentWallet.verifyPassword(password)) {
                    qtobject.authProceed()
                } else {
                    console.warn("Biometric password invalid falling back to manual input")
                    // this shouldn't really happen so we better disable biometric auth
                    Biometrics.disable()
                    handleManualAuth(qtobject, method, app._pendingBiometricAuth.authMessage)
                }
                app._pendingBiometricAuth = null
            }
        }

        function onUnlockError(error) {
            console.log("Biometric auth failed: " + error)
            // we end up here if QEBiometrics fails to give us the decrypted password. The user might
            // have cancelled the biometric auth popup or the key got invalidated because a new fingerprint got registered.
            if (app._pendingBiometricAuth) {
                if (app._pendingBiometricAuth.action === 'load_wallet') {
                    // set loadingWalletContext to disable biometric auth until the OpenWalletDialog is closed
                    app._loadingWalletContext = app._pendingBiometricAuth
                    showOpenWalletDialog(app._pendingBiometricAuth.name, app._pendingBiometricAuth.path)
                } else {
                    console.log('biometric auth failed, not falling back to passwordDialog')
                    app._pendingBiometricAuth.qtobject.authCancel()  // no fallback to password dialog
                }
                app._pendingBiometricAuth = null
            }
        }

        function onAuthRequired(method, authMessage) {
            handleAuthRequired(Biometrics, method, authMessage)
        }
    }

    property var _opendialog: null
    property var _opendialog_startup: true

    function showOpenWalletDialog(name, path) {
        if (!_opendialog) {
            _opendialog = openWalletDialog.createObject(app, {
                name: name,
                path: path,
                isStartup: _opendialog_startup,
            })
            _opendialog.closed.connect(function() {
                _opendialog = null
                app._loadingWalletContext = null  // dialog closed, we can allow trying biometric auth again
                _opendialog_startup = false
            })
            _opendialog.open()
        }
    }

    function showStartupWarnings() {
        if (!Daemon.currentWallet)
            return
        let warnings = Daemon.currentWallet.startupWarnings
        // show the warnings one after another, as the dialogs are not modal
        function showWarning(i) {
            if (i >= warnings.length)
                return
            let dialog = app.messageDialog.createObject(app, {
                title: warnings[i].title,
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: warnings[i].message
            })
            dialog.accepted.connect(function() {
                Daemon.currentWallet.acknowledgeWarning(warnings[i].key)
            })
            dialog.closed.connect(function() {
                showWarning(i + 1)
            })
            dialog.open()
        }
        showWarning(0)
    }

    Connections {
        target: Daemon
        function onWalletRequiresPassword(name, path) {
            console.log('wallet requires password')
            if (Biometrics.isAvailable && Biometrics.isEnabled && !app._loadingWalletContext) {
                if (!app._pendingBiometricAuth) {
                    app._pendingBiometricAuth = {
                        action: 'load_wallet',
                        name: name,
                        path: path
                    }
                    Biometrics.unlock()
                }
            } else {
                showOpenWalletDialog(name, path)
            }
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
        function onWalletLoaded() {
            app._loadingWalletContext = null  // either biometric auth or manual auth was successful
            showStartupWarnings()
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
        function onPluginLoaded(name) {
            console.log('plugin ' + name + ' loaded')
            var loader = AppController.plugin(name).loader
            if (loader == undefined)
                return
            var url = Qt.resolvedUrl('../../../plugins/' + name + '/qml/' + loader)
            var comp = Qt.createComponent(url)
            if (comp.status == Component.Error) {
                console.log('Could not find/parse PluginLoader for plugin ' + name)
                console.log(comp.errorString())
                return
            }
            var obj = comp.createObject(app)
            if (obj != null)
                app.pluginobjects[name] = obj
        }
        function onUriReceived(uri) {
            console.log('uri received (main): ' + uri)
            app.pendingIntent = uri
        }
    }

    function pluginsComponentsByName(comp_name) {
        // return named QML components from plugins
        var plugins = AppController.plugins
        var result = []
        for (var i=0; i < plugins.length; i++) {
            if (!plugins[i].enabled)
                continue
            var pluginobject = app.pluginobjects[plugins[i].name]
            if (!pluginobject)
                continue
            if (!(comp_name in pluginobject))
                continue
            var comp = pluginobject[comp_name]
            if (!comp)
                continue

            result.push(comp)
        }
        return result
    }

    Connections {
        target: Daemon.currentWallet
        function onAuthRequired(method, authMessage) {
            handleAuthRequired(Daemon.currentWallet, method, authMessage)
        }
        // TODO: add to notification queue instead of barging through
        function onPaymentSucceeded(key) {
            notificationPopup.show(Daemon.currentWallet.name, qsTr('Payment succeeded'))
        }
        function onPaymentFailed(key, reason) {
            notificationPopup.show(Daemon.currentWallet.name, qsTr('Payment failed') + ': ' + reason)
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

        if (method === 'payment_auth') {
            if (Config.paymentAuthentication) {
                // treat like a wallet auth request
                method = 'wallet'
            } else {
                handleAuthConfirmationOnly(qtobject, authMessage)
                return
            }
        }

        if (Daemon.currentWallet.verifyPassword('')) {
            // wallet has no password
            qtobject.authProceed()
            return
        }

        if (method !== 'wallet_password_only') {
            if (Biometrics.isAvailable && Biometrics.isEnabled) {
                if (!app._pendingBiometricAuth) {
                    app._pendingBiometricAuth = {
                        qtobject: qtobject,
                        method: method,
                        authMessage: authMessage
                    }
                    Biometrics.unlock(authMessage)
                }
                return
            }
        }

        handleManualAuth(qtobject, method, authMessage)
    }

    function handleManualAuth(qtobject, method, authMessage) {
        // 'payment_auth' should have been converted to 'wallet' at this point
        if (method === 'wallet' || method === 'wallet_password_only') {
            var dialog = app.passwordDialog.createObject(app, authMessage ? {'title': authMessage} : {})
            dialog.passwordEntered.connect(function(password) {
                if (Daemon.currentWallet.verifyPassword(password)) {
                    dialog.close()
                    qtobject.authProceed()
                } else {
                    dialog.clearPassword()
                    dialog.errorMessage = qsTr("Invalid Password")
                }
            })
            dialog.rejected.connect(function() {
                qtobject.authCancel()
            })
            dialog.open()
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


    // We want all Text/Label/etc components to use PlainText by default.
    // Qt normally defaults to AutoText, which allows rich text.
    // For our Android builds, we patch Qt at compile-time to change this.
    // (see "qt-6-10-rich-text-should-be-opt-in.patch")
    // FIXME other platforms? (e.g. running QML on desktop Linux / dev environment)
    // This runtime check here aims to prevent regressions by hard-failing.
    Label {
        id: richtext_sanity_label
        Component.onCompleted: {
            if (richtext_sanity_label.textFormat !== 0 && AppController.isAndroid()) {
                console.log(
                    "richtext_sanity_label failed check: expected PlainText, "
                    + "got " + richtext_sanity_label.textFormat + ". Exiting...")
                app.quitApp()
            }
        }
    }
}
