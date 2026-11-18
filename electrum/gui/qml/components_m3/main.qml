import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Basic
import QtQuick.Controls.Material
import QtQuick.Window

import QtQml

import org.electrum 1.0

import "controls"

// Window of the Material 3 GUI (qml_ui_style = 'material3'), loaded instead of components/main.qml.
// Everything non-visual is carried over verbatim from components/main.qml @ 4f36c4489: the `app`
// contract the classic screens rely on (stack, keyboardFreeZone, infobanner, dialog factories,
// activeDialogs, ...), the handlers of Daemon / Biometrics / AppController / Config, authentication,
// startup and onClosing. Differences from the original are marked with `// M3:`.
// The window keeps the classic dark theme (as components/main.qml); Material 3 pages and popups set their
// own (light or dark) theme from `m3` (M3Theme.qml).
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
    font.pixelSize: 15  // M3: repeats components/Constants.qml fontSizeMedium

    // M3: Material 3 theme (color roles, type scale, shapes)
    property QtObject m3: m3theme
    M3Theme { id: m3theme }

    // M3: routes, one URL per page that Material 3 code opens (M3Routes.qml); open them with pushPage/loadPage
    property QtObject routes: m3routes
    M3Routes { id: m3routes }

    // M3: the message when a Material 3 screen could not be opened (its file does not load, or its page could not be
    // created; the details are in the log). There is no classic screen to fall back to: the message offers the way
    // back to the classic interface of the overflow menu (showRestartDialog). One message at a time.
    property var _screenErrorDialog: null
    function showScreenError() {
        if (_screenErrorDialog)
            return _screenErrorDialog
        var dialog = app.messageDialog.createObject(app, {
            title: qsTr('Screen unavailable'),
            iconSource: Qt.resolvedUrl('../../icons/m3/warning.png'),
            text: qsTr('This screen could not be opened (details in the log). Switch to the classic interface?'),
            yesno: true
        })
        _screenErrorDialog = dialog
        dialog.closed.connect(function() {
            app._screenErrorDialog = null
        })
        dialog.accepted.connect(function() {
            app.showRestartDialog()
        })
        dialog.open()
        return dialog
    }

    // M3: the ready component of the page at `url`; when it cannot be loaded, null, the error in the log and the
    // message of showScreenError. The stack only gets ready components (stackPage).
    function loadPage(url) {
        var component = Qt.createComponent(url)
        if (component.status === Component.Ready)
            return component
        console.log('M3: cannot load ' + url + ': ' + component.errorString())
        showScreenError()
        return null
    }

    // M3: puts the page of the ready `component` with `properties` on the stack: pushed, or in place of `target`
    // (StackView.replace: `target` and the pages above it); `component` may also be a page made by makePage (its
    // properties are set already). Returns the page, and calls `done(page)` when given;
    // returns null when there is no page yet (`failed()` is called when given, if the page could not be created):
    // - the page could not be created: StackView then leaves an empty element on top and keeps drawing the
    //   half-made page and a replaced one (measured on Qt 6.10): the empty elements are taken off, those leftovers
    //   hidden, the error logged and showScreenError shown;
    // - the stack refused it: StackView refuses an operation asked while it completes a push (e.g. from
    //   Component.onCompleted of the page it is pushing), returns nothing and stays as it was. That is no broken
    //   screen: no message; the operation is asked once more after the current event (Qt.callLater), and `done`
    //   gets the page then.
    function stackPage(component, properties, target, done, failed, _retry) {
        var made = _madeEntry(component)
        var name = made ? String(component) : component.url
        var props = made ? {} : (properties ? properties : {})
        var before = []
        for (var i = 0; i < mainStackView.depth; i++)
            before.push(mainStackView.get(i))
        if (target && before.indexOf(target) < 0) {
            console.log('M3: ' + name + ' not shown: the page it was to replace is gone')
            _dropMadePage(component)
            return null
        }
        var children = []
        for (var c = 0; c < mainStackView.children.length; c++)
            children.push(mainStackView.children[c])

        var page = target
            ? mainStackView.replace(target, component, props)
            : mainStackView.push(component, props)

        var depth = mainStackView.depth
        if (made || (depth > 0 && mainStackView.get(depth - 1) !== null)) {
            if (page) {
                if (made)
                    made.placed = true
                if (done)
                    done(page)
                return page
            }
            if (_retry) {
                console.log('M3: the stack refused ' + name + ' again, not shown')
                _dropMadePage(component)
            } else {
                console.log('M3: the stack is busy, ' + name + ' is asked again after this event')
                Qt.callLater(function() {
                    app.stackPage(component, properties, target, done, failed, true)
                })
            }
            return null
        }

        console.log('M3: cannot create the page of ' + component.url + ' (see the error above)')
        while (mainStackView.depth > 1 && mainStackView.get(mainStackView.depth - 1) === null)
            mainStackView.pop(StackView.Immediate)
        if (mainStackView.depth === 1 && mainStackView.get(0) === null)
            mainStackView.clear(StackView.Immediate)
        var kept = []
        for (var k = 0; k < mainStackView.depth; k++)
            kept.push(mainStackView.get(k))
        for (var h = 0; h < mainStackView.children.length; h++) {
            var child = mainStackView.children[h]
            if (kept.indexOf(child) < 0 && (children.indexOf(child) < 0 || before.indexOf(child) >= 0))
                child.visible = false
        }
        showScreenError()
        if (failed)
            failed()
        return null
    }

    // M3: the page of the ready `component` made with `properties` before it goes on the stack, for a page that
    // takes the place of another one (stackPage with `target`): StackView.replace takes the target off the stack
    // before it creates the new page, so a page that cannot be created would take the page on top with it (e.g.
    // SendPage with the input). Returns the page (hidden until stackPage shows it), or null when it cannot be created
    // (the error in the log, showScreenError; nothing on the stack changed).
    // StackView destroys only the pages it made itself: a made page is destroyed here when it has been on the stack
    // and has left it (after the transition), or when stackPage does not show it.
    property var _madePages: []
    function makePage(component, properties) {
        var page = component.createObject(mainStackView, Object.assign({}, properties ? properties : {}, { visible: false }))
        if (!page) {
            console.log('M3: cannot create the page of ' + component.url + ' (see the error above)')
            showScreenError()
            return null
        }
        _madePages.push({ page: page, placed: false })
        return page
    }
    function _madeEntry(item) {
        for (var i = 0; i < _madePages.length; i++)
            if (_madePages[i].page === item)
                return _madePages[i]
        return null
    }
    function _dropMadePage(item) {
        var entry = _madeEntry(item)
        if (!entry)
            return
        _madePages.splice(_madePages.indexOf(entry), 1)
        item.destroy()
    }
    function _dropMadePages() {
        if (mainStackView.busy)
            return
        var onStack = []
        for (var i = 0; i < mainStackView.depth; i++)
            onStack.push(mainStackView.get(i))
        _madePages = _madePages.filter(function(entry) {
            if (!entry.page)
                return false  // destroyed already (with the window)
            if (!entry.placed || onStack.indexOf(entry.page) >= 0)
                return true
            entry.page.destroy()
            return false
        })
    }

    // M3: pushes the page at `url` (a route) with `properties`; returns the page, or null when no page
    // was shown (stackPage; the stack is then unchanged)
    function pushPage(url, properties) {
        var component = loadPage(url)
        if (!component)
            return null
        return stackPage(component, properties)
    }

    // M3: as pushPage, in place of the page above the root (pages opened from the overflow menu, the tabs and the
    // chips replace each other instead of piling up)
    function pushPageOnRoot(url) {
        var component = loadPage(url)
        if (!component)
            return null
        return stackPage(component, {}, mainStackView.depth > 1 ? mainStackView.get(1) : null)
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
            // M3: the Material 3 settings: the Settings tab on the root of a wallet, else the settings page
            text: qsTranslate('WalletMainView', 'Settings')
            onTriggered: {
                if (app._m3WalletRoot)
                    mainStackView.get(0).currentTab = 3
                else
                    m3Menu.openPage(app.routes.preferences)
            }
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

            // M3-39: "Close Electrum" closes the app only from onClosed, once this dialog is off the screen, and the dialog
            // closes without its exit animation. A dialog still on the screen when the window is destroyed (its animation
            // stops with the event loop) lays out its text again after the Qt GUI application is gone: SIGABRT on Android.
            // Without the animation `closed` comes at once (inside doAccept), so no back key or page change gets in between.
            property bool _closeApp: false

            function choose(close_app) {
                Config.uiStyle = 'classic'
                if (close_app) {
                    restartDialog._closeApp = true
                    restartDialog.exit = null
                }
                restartDialog.doAccept()
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

            onClosed: {
                var closeApp = restartDialog._closeApp
                destroy()
                if (closeApp) {
                    // same path as the confirmation of "Close Electrum?" in onClosing
                    AppController.wantClose = true
                    app.close()
                }
            }
        }
    }

    // M3: Material 3 top app bar for every page: back arrow on pushed
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
                Wallets {}
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
            // M3: screens pass bare file names (Wallets.qml: 'WalletMainView.qml', PaymentFlow after
            // a wallet was deleted: 'Wallets.qml'); they resolve relative to components_m3/. A root that cannot be
            // loaded leaves the stack as it is (app.loadPage shows the message); a root whose page cannot be created
            // leaves the Wallets page as the root (app.stackPage shows the message).
            function replaceRoot(item_url, _retry) {
                var component = app.loadPage(Qt.resolvedUrl(item_url))
                if (!component)
                    return
                mainStackView.clear()
                if (mainStackView.depth > 0) {
                    // the stack refused the clear (as in stackPage: asked while it completes a push): the whole
                    // replacement once more after this event (a repeat of the push alone would pile the root up)
                    if (_retry) {
                        console.log('M3: the stack refused ' + item_url + ' again, not shown')
                    } else {
                        console.log('M3: the stack is busy, ' + item_url + ' is asked again after this event')
                        Qt.callLater(function() { mainStackView.replaceRoot(item_url, true) })
                    }
                    return
                }
                app.stackPage(component, {}, null, null, function() {
                    if (item_url !== 'Wallets.qml' && mainStackView.depth === 0)
                        replaceRoot('Wallets.qml')
                })
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
            onCurrentItemChanged: {
                updateStylingFromItem(currentItem)
                Qt.callLater(app._dropMadePages)
            }
            // M3: the pages made by app.makePage that left the stack are destroyed when the transition is over
            onBusyChanged: {
                if (!busy)
                    app._dropMadePages()
            }
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
        // M3: the Material 3 wizard (components_m3/NewWalletWizard.qml)
        NewWalletWizard {
            onClosed: destroy()
        }
    }

    property alias termsOfUseWizard: _termsOfUseWizard
    Component {
        id: _termsOfUseWizard
        // M3: the Material 3 wizard (components_m3/TermsOfUseWizard.qml)
        TermsOfUseWizard {
            onClosed: destroy()
        }
    }

    property alias serverConnectWizard: _serverConnectWizard
    Component {
        id: _serverConnectWizard
        // M3: the Material 3 wizard (components_m3/ServerConnectWizard.qml)
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

    property alias genericShareDialog: _genericShareDialog
    Component {
        id: _genericShareDialog
        ShareDialog {
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
        ScanDialog {}
    }

    Component {
        id: crashDialog
        ExceptionDialog {
            onClosed: destroy()
        }
    }

    property alias channelOpenProgressDialog: _channelOpenProgressDialog
    ChannelOpenProgressDialog {
        id: _channelOpenProgressDialog
    }

    // M3: one factory for "Open channel" (the Channels tab and BalanceDetails, M2-MAP F-12), the Material 3 dialog
    property alias openChannelDialog: _openChannelDialog
    Component {
        id: _openChannelDialog
        OpenChannelDialog {
            onClosed: destroy()
        }
    }

    property alias signVerifyMessageDialog: _signVerifyMessageDialog
    Component {
        id: _signVerifyMessageDialog
        SignVerifyMessageDialog {
            onClosed: destroy()
        }
    }

    property alias nostrSwapServersDialog: _nostrSwapServersDialog
    Component {
        id: _nostrSwapServersDialog
        NostrSwapServersDialog {
            onClosed: destroy()
        }
    }

    Component {
        id: swapDialog
        SwapDialog {
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
                        iconSource: Qt.resolvedUrl('../../icons/m3/warning.png'),
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

    NotificationPopup {
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
                iconSource: Qt.resolvedUrl('../../icons/m3/warning.png'),
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
                iconSource: Qt.resolvedUrl('../../icons/m3/warning.png'),
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
            var plugin = AppController.plugin(name)
            if (!plugin)  // M3: a plugin without a QML object (AppController.plugin() returns None)
                return
            var loader = plugin.loader
            if (loader == undefined)
                return
            // M3: the Material 3 QML of the plugin (plugins/<name>/qml_m3/, M2-MAP F-11); a plugin without it has no
            // QML in Material 3 (its classic QML is not loaded)
            var base = '../../../plugins/' + name
            var comp = Qt.createComponent(Qt.resolvedUrl(base + '/qml_m3/' + loader))
            if (comp.status == Component.Error) {
                console.log('M3: no Material 3 QML (qml_m3/' + loader + ') for plugin ' + name + ', its QML is not loaded')
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
