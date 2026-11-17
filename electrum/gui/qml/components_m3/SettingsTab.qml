import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// Settings tab: all settings of the classic Preferences screen, grouped, plus the interface style
// and the Material 3 theme; Network, About and the classic Preferences screen open full screen.
//
// repeats: components/Preferences.qml:44-492 (settings, conditions, confirmations), :497-514
// (initial values) @ 4f36c4489; the language restart dialog repeats the form of
// components_m3/main.qml showRestartDialog() (interface style).
//
// Every control SHOWS a binding to the backend property and WRITES only on a user action
// (userToggled / selected / moved / activated), so opening the screen writes nothing, and a write
// refused by the backend (a password prompt cancelled, a confirmation declined) leaves the control
// on the backend value. Classic strings keep the classic original under the 'Preferences' context.
Item {
    id: root

    readonly property var _baseunits: ['BTC', 'mBTC', 'bits', 'sat']
    readonly property var _fees: [500, 1000, 3000, 5000, 10000, 20000, 30000, 50000]
    readonly property bool _isAndroid: AppController.isAndroid()

    // Values without a change signal (the plugin state; Config.setMaxBrightnessOnQrDisplay, whose
    // setter emits nothing) are kept here and read again after a write and whenever the tab is
    // shown (the classic Preferences screen, opened from "More", may have changed them).
    property bool _labelsEnabled: false
    property bool _psbtNostrEnabled: false
    property bool _maxBrightness: false

    function _readUnsignalled() {
        _labelsEnabled = AppController.isPluginEnabled('labels')
        _psbtNostrEnabled = AppController.isPluginEnabled('psbt_nostr')
        _maxBrightness = Config.setMaxBrightnessOnQrDisplay
    }

    // This tab lives for the whole session, while the classic Preferences screen is created on
    // each opening. Bindings to a value read through a slot (whether the wallet has a password,
    // changed in Wallet details, a page over this tab) depend on this, so the value is read again
    // whenever the tab is shown.
    property int _shownRevision: 0

    // Biometrics.enable() is also called by Wallet details and the classic Preferences screen, each
    // with its own enablingFailed handler; only a failure of an enabling started here is shown here.
    // Set when this tab starts one, cleared by its outcome and when the tab is hidden: the system
    // biometric prompt does not hide it, every other caller is a page over it.
    property bool _enablingBiometrics: false

    function _setPlugin(name, enabled) {
        AppController.setPluginEnabled(name, enabled)
        _readUnsignalled()
    }

    function _confirm(title, text, onYes) {
        var dialog = confirmDialog.createObject(app, { title: title, text: text })
        dialog.accepted.connect(onYes)
        dialog.open()
    }

    function _message(title, text) {
        var dialog = messageDialog.createObject(app, { title: title, text: text })
        dialog.open()
    }

    Component.onCompleted: _readUnsignalled()
    onVisibleChanged: {
        if (visible) {
            _readUnsignalled()
            _shownRevision++
        } else {
            _enablingBiometrics = false
        }
    }

    Connections {
        target: Biometrics
        function onEnablingFailed(error) {
            if (!root._enablingBiometrics)
                return // started elsewhere, which shows its own message
            root._enablingBiometrics = false
            if (error === 'CANCELLED')
                return // don't show error popup
            root._message('', qsTranslate('Preferences', 'Failed to enable biometric authentication: ') + error)
        }
        function onIsEnabledChanged() {
            // enabled: done. A failure first disables (isEnabled false), then emits enablingFailed
            if (Biometrics.isEnabled)
                root._enablingBiometrics = false
        }
    }

    Flickable {
        anchors.fill: parent
        contentHeight: column.implicitHeight + 2 * m3.space16
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        ScrollIndicator.vertical: ScrollIndicator {}

        ColumnLayout {
            id: column
            y: m3.space8
            width: Math.min(parent.width, m3.maxContentWidth) - 2 * m3.screenMargin(parent.width)
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: 0

            // ---------------------------------------------------------------- Appearance
            M3SectionHeader {
                Layout.fillWidth: true
                text: qsTr('Appearance')
            }

            M3ListGroup {
                Layout.fillWidth: true

                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.margins: m3.space16
                    spacing: m3.space8

                    M3Text {
                        role: 'bodyLarge'
                        text: qsTranslate('Preferences', 'Interface style')
                    }
                    M3SegmentedButton {
                        Layout.fillWidth: true
                        model: [
                            { text: qsTranslate('Preferences', 'Classic'), value: 'classic' },
                            { text: qsTranslate('Preferences', 'Material 3'), value: 'material3' }
                        ]
                        // the saved setting; this GUI runs Material 3 until restarted
                        currentValue: Config.uiStyle == 'material3' ? 'material3' : 'classic'
                        onActivated: (value) => {
                            if (value == 'classic')
                                app.showRestartDialog()  // writes the setting unless cancelled
                            else
                                Config.uiStyle = 'material3'
                        }
                    }
                    M3Text {
                        Layout.fillWidth: true
                        role: 'bodySmall'
                        color: m3.surfaceVariantOn
                        wrapMode: Text.Wrap
                        text: Config.uiStyle == 'material3'
                            ? qsTr('Applies after restart')
                            : qsTr('Now: Material 3; after restart: Classic')
                    }
                }

                M3SelectRow {
                    headline: qsTr('Theme')
                    model: [
                        { text: qsTr('System'), value: 'system' },
                        { text: qsTr('Light'), value: 'light' },
                        { text: qsTr('Dark'), value: 'dark' }
                    ]
                    currentValue: Config.m3Theme == 'light' || Config.m3Theme == 'dark' ? Config.m3Theme : 'system'
                    onSelected: (value) => { Config.m3Theme = value }
                }

                M3SelectRow {
                    headline: qsTranslate('Preferences', 'Language')
                    model: Config.languagesAvailable
                    currentValue: Config.language
                    // written only by "Close Electrum" / "On next start" of the restart dialog
                    onSelected: (value) => {
                        if (value != Config.language)
                            languageDialog.createObject(app, { language: value }).open()
                    }
                }

                M3SwitchRow {
                    headline: qsTranslate('Preferences', 'Increase brightness when displaying QR codes')
                    headlineMaxLines: 2
                    enabled: root._isAndroid
                    checked: root._maxBrightness && root._isAndroid
                    onUserToggled: (checked) => {
                        Config.setMaxBrightnessOnQrDisplay = checked
                        root._readUnsignalled()
                    }
                }
            }

            // ---------------------------------------------------------------- Amounts
            M3SectionHeader {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                text: qsTr('Amounts')
            }

            M3ListGroup {
                Layout.fillWidth: true

                M3SelectRow {
                    headline: qsTranslate('Preferences', 'Base unit')
                    model: root._baseunits
                    currentValue: Config.baseUnit
                    onSelected: (value) => { Config.baseUnit = value }
                }

                M3SwitchRow {
                    headline: qsTranslate('Preferences', 'Add thousands separators to bitcoin amounts')
                    headlineMaxLines: 2
                    checked: Config.thousandsSeparator
                    onUserToggled: (checked) => { Config.thousandsSeparator = checked }
                }

                M3SwitchRow {
                    headline: qsTranslate('Preferences', 'Fiat Currency')
                    checked: Daemon.fx.enabled
                    onUserToggled: (checked) => { Daemon.fx.enabled = checked }
                }

                M3SelectRow {
                    headline: qsTr('Currency')
                    enabled: Daemon.fx.enabled
                    model: {
                        // the list depends on the historic-rates switch, but currenciesChanged is
                        // never emitted: follow historicRatesChanged, from this tab or the classic screen
                        Daemon.fx.historicRates
                        return Daemon.fx.currencies
                    }
                    currentValue: Daemon.fx.fiatCurrency
                    onSelected: (value) => { Daemon.fx.fiatCurrency = value }
                }

                M3SwitchRow {
                    headline: qsTranslate('Preferences', 'Historic rates')
                    enabled: Daemon.fx.enabled
                    checked: Daemon.fx.historicRates
                    onUserToggled: (checked) => { Daemon.fx.historicRates = checked }
                }

                M3SelectRow {
                    headline: qsTranslate('Preferences', 'Exchange rate provider')
                    headlineMaxLines: 2
                    enabled: Daemon.fx.enabled
                    // the list follows the currency and the historic-rates switch
                    model: Daemon.fx.rateSources
                    currentValue: Daemon.fx.rateSource
                    onSelected: (value) => { Daemon.fx.rateSource = value }
                }
            }

            // ---------------------------------------------------------------- Security
            M3SectionHeader {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                text: qsTranslate('Preferences', 'Security')
            }

            M3ListGroup {
                Layout.fillWidth: true

                M3SwitchRow {
                    // read again when the tab is shown (see _shownRevision): no signal follows a
                    // password set or removed in Wallet details
                    readonly property bool noWalletPassword: {
                        root._shownRevision
                        return Daemon.currentWallet ? Daemon.currentWallet.verifyPassword('') : true
                    }
                    headline: qsTranslate('Preferences', 'Request authentication for payments')
                    headlineMaxLines: 2
                    enabled: !!Daemon.currentWallet && !noWalletPassword
                    // showing the toggle as checked even if the wallet has no password would be misleading
                    checked: Config.paymentAuthentication && !(Daemon.currentWallet && noWalletPassword)
                    // turning it off asks for the wallet password (Config.onAuthRequired);
                    // a refusal emits paymentAuthenticationChanged and the binding shows "on" again
                    onUserToggled: (checked) => { Config.paymentAuthentication = checked }
                }

                M3SwitchRow {
                    headline: qsTranslate('Preferences', 'Biometric authentication')
                    headlineMaxLines: 2
                    // isAvailable checks phone support and if a fingerprint is enrolled on the system
                    enabled: Biometrics.isAvailable && !!Daemon.currentWallet
                    checked: Biometrics.isEnabled
                    onUserToggled: (checked) => {
                        if (!checked) {
                            Biometrics.disableProtected()
                        } else if (Daemon.singlePasswordEnabled) {
                            root._enablingBiometrics = true
                            Biometrics.enable(Daemon.singlePassword)
                        } else {
                            root._message(qsTranslate('Preferences', 'Unavailable'), [
                                qsTranslate('Preferences', 'Cannot activate biometric authentication because you have wallets with different passwords.'),
                                qsTranslate('Preferences', 'To use biometric authentication you first need to change all wallet passwords to the same password.')
                            ].join('\n'))
                        }
                    }
                }

                M3SwitchRow {
                    headline: qsTranslate('Preferences', 'Protect secrets from screenshots')
                    headlineMaxLines: 2
                    enabled: root._isAndroid
                    checked: !Config.alwaysAllowScreenshots && root._isAndroid
                    onUserToggled: (checked) => { Config.alwaysAllowScreenshots = !checked }
                }
            }

            // ---------------------------------------------------------------- Wallet behavior
            M3SectionHeader {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                text: qsTranslate('Preferences', 'Wallet behavior')
            }

            M3ListGroup {
                Layout.fillWidth: true

                M3SwitchRow {
                    headline: qsTranslate('Preferences', 'Spend unconfirmed')
                    headlineMaxLines: 2
                    checked: Config.spendUnconfirmed
                    onUserToggled: (checked) => { Config.spendUnconfirmed = checked }
                }

                M3SwitchRow {
                    headline: Config.shortDescFor('WALLET_FREEZE_REUSED_ADDRESS_UTXOS')
                    headlineMaxLines: 3
                    checked: Config.freezeReusedAddressUtxos
                    onUserToggled: (checked) => { Config.freezeReusedAddressUtxos = checked }
                }
            }

            // ---------------------------------------------------------------- Lightning
            M3SectionHeader {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                text: qsTranslate('Preferences', 'Lightning')
            }

            M3ListGroup {
                Layout.fillWidth: true

                M3SliderRow {
                    readonly property int feeIndex: root._fees.indexOf(Config.lightningPaymentFeeMaxMillionths)
                    headline: Config.shortDescFor('LIGHTNING_PAYMENT_FEE_MAX_MILLIONTHS')
                    // the classic string, without its rich-text bold (M3Text is plain text); as the
                    // supporting line, which wraps, so that a long headline is not elided
                    supporting: qsTranslate('Preferences', '<b>%1%</b> of payment')
                        .arg(Config.lightningPaymentFeeMaxMillionths / 10000)
                        .replace(/<\/?b>/g, '')
                    from: 0
                    to: root._fees.length - 1
                    stepSize: 1
                    snapMode: Slider.SnapAlways
                    value: Math.max(0, feeIndex)
                    onMoved: (value) => {
                        var fee = root._fees[Math.round(value)]
                        if (fee !== undefined && fee != Config.lightningPaymentFeeMaxMillionths)
                            Config.lightningPaymentFeeMaxMillionths = fee
                    }
                }

                M3SwitchRow {
                    headline: qsTranslate('Preferences', 'Trampoline routing')
                    headlineMaxLines: 2
                    checked: !Config.useGossip  // inverted
                    onUserToggled: (checked) => {
                        if (checked) {
                            Config.useGossip = false
                        } else {
                            root._confirm(qsTranslate('Preferences', 'Are you sure?'),
                                qsTranslate('Preferences', 'Electrum will have to download the Lightning Network graph, which is not recommended on mobile.'),
                                function() { Config.useGossip = true })
                        }
                    }
                }

                M3SwitchRow {
                    headline: qsTranslate('Preferences', 'Create recoverable channels')
                    headlineMaxLines: 2
                    checked: Config.useRecoverableChannels
                    onUserToggled: (checked) => {
                        if (checked) {
                            Config.useRecoverableChannels = true
                        } else {
                            root._confirm(qsTranslate('Preferences', 'Are you sure?'),
                                qsTranslate('Preferences', 'This option allows you to recover your lightning funds if you lose your device, or if you uninstall this app while lightning channels are active. Do not disable it unless you know how to recover channels from backups.'),
                                function() { Config.useRecoverableChannels = false })
                        }
                    }
                }
            }

            // ---------------------------------------------------------------- Advanced
            M3SectionHeader {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                text: qsTranslate('Preferences', 'Advanced')
            }

            M3ListGroup {
                Layout.fillWidth: true

                M3SwitchRow {
                    headline: qsTranslate('Preferences', 'Synchronize labels')
                    headlineMaxLines: 2
                    checked: root._labelsEnabled
                    onUserToggled: (checked) => root._setPlugin('labels', checked)
                }

                M3SwitchRow {
                    headline: qsTranslate('Preferences', 'Nostr Cosigner')
                    headlineMaxLines: 2
                    checked: root._psbtNostrEnabled
                    onUserToggled: (checked) => root._setPlugin('psbt_nostr', checked)
                }

                M3SwitchRow {
                    headline: qsTranslate('Preferences', 'Enable debug logs (for developers)')
                    headlineMaxLines: 2
                    enabled: Config.canToggleDebugLogs
                    checked: Config.enableDebugLogs
                    onUserToggled: (checked) => { Config.enableDebugLogs = checked }
                }
            }

            // ---------------------------------------------------------------- More
            M3SectionHeader {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                text: qsTr('More')
            }

            M3ListGroup {
                Layout.fillWidth: true

                M3ListItem {
                    headline: qsTranslate('Preferences', 'Preferences')
                    supporting: qsTr('All settings (classic screen)')
                    leadingIcon: Qt.resolvedUrl('../../icons/m3/settings.png')
                    trailing: chevron
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/Preferences.qml'))
                }
                M3ListItem {
                    headline: qsTr('Network')
                    supporting: Network.isConnected ? Network.server : qsTr('Disconnected')
                    leadingIcon: Qt.resolvedUrl(Network.isConnected ? '../../icons/m3/sync.png' : '../../icons/m3/cloud_off.png')
                    trailing: chevron
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/NetworkOverview.qml'))
                }
                M3ListItem {
                    headline: qsTranslate('main', 'About')
                    leadingIcon: Qt.resolvedUrl('../../icons/m3/info.png')
                    trailing: chevron
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/About.qml'))
                }
            }

            Flow {
                Layout.fillWidth: true
                Layout.topMargin: m3.space16
                spacing: m3.space8

                M3Chip {
                    visible: Network.isTestNet
                    tone: 'tertiary'
                    iconSource: Qt.resolvedUrl('../../icons/m3/info.png')
                    text: Network.networkName
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/NetworkOverview.qml'))
                }
                M3Chip {
                    tone: Network.isConnected ? '' : 'error'
                    iconSource: Qt.resolvedUrl(Network.isConnected ? '../../icons/m3/check_circle.png' : '../../icons/m3/cloud_off.png')
                    text: Network.isConnected ? qsTr('Connected') : qsTr('Disconnected')
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/NetworkOverview.qml'))
                }
            }
        }
    }

    Component {
        id: chevron
        M3Icon {
            source: Qt.resolvedUrl('../../icons/m3/chevron_right.png')
            color: m3.surfaceVariantOn
        }
    }

    // Language change: the same three choices as the interface style (main.qml showRestartDialog);
    // Config.language is written only by "Close Electrum" and "On next start", "Cancel" changes nothing.
    Component {
        id: languageDialog
        M3Dialog {
            id: dialog

            property string language

            title: qsTranslate('Preferences', 'Language')
            text: qsTranslate('Preferences', 'Please restart Electrum to activate the new GUI settings')

            function choose(close_app) {
                Config.language = dialog.language
                dialog.doAccept()
                if (close_app) {
                    // same path as the confirmation of "Close Electrum?" in onClosing
                    AppController.wantClose = true
                    app.close()
                }
            }

            buttons: [
                M3Button {
                    variant: 'text'
                    text: qsTranslate('main', 'Close Electrum')
                    onClicked: dialog.choose(true)
                },
                M3Button {
                    variant: 'text'
                    text: qsTranslate('main', 'On next start')
                    onClicked: dialog.choose(false)
                },
                M3Button {
                    variant: 'text'
                    text: qsTranslate('main', 'Cancel')
                    onClicked: dialog.doReject()
                }
            ]

            onClosed: destroy()
        }
    }

    // "Are you sure?" with No / Yes; accepted only by Yes (the switch stays on the backend value otherwise)
    Component {
        id: confirmDialog
        M3Dialog {
            id: dialog
            buttons: [
                M3Button {
                    variant: 'text'
                    text: qsTranslate('MessageDialog', 'Yes')
                    onClicked: dialog.doAccept()
                },
                M3Button {
                    variant: 'text'
                    text: qsTranslate('MessageDialog', 'No')
                    onClicked: dialog.doReject()
                }
            ]
            onClosed: destroy()
        }
    }

    Component {
        id: messageDialog
        M3Dialog {
            id: dialog
            buttons: [
                M3Button {
                    variant: 'text'
                    text: qsTranslate('MessageDialog', 'Ok')
                    onClicked: dialog.doAccept()
                }
            ]
            onClosed: destroy()
        }
    }
}
