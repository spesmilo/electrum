import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// Root of the stack in the Material 3 GUI: the tabs Wallet / Channels / History / Settings.
// The file name matches the classic components/WalletMainView.qml on purpose: the classic
// Wallets.qml calls app.stack.replaceRoot('WalletMainView.qml') after a wallet is loaded, and
// replaceRoot in components_m3/main.qml resolves names relative to components_m3/.
// Duties towards the classic screens: openInvoice (Invoices.qml), openRequest (ReceiveRequests.qml),
// showExport (TxDetails.qml), an objectName other than 'Wallets' (Wallets.qml); the reaction to a
// deleted wallet lives in PaymentFlow (Daemon.onWalletLoaded).
M3Page {
    id: root
    objectName: 'M3WalletMainView'

    readonly property bool m3WalletRoot: true

    property int currentTab: 0

    readonly property var _tabTitles: [
        Daemon.currentWallet ? Daemon.currentWallet.name : '',
        qsTr('Channels'),
        qsTr('History'),
        qsTr('Settings')
    ]
    title: _tabTitles[currentTab]

    // header subtitle (read by the top app bar in main.qml)
    property string subtitle: currentTab == 0 && Daemon.currentWallet
        ? (Daemon.currentWallet.isLightning ? qsTr('Lightning') : qsTr('On-chain only'))
            + (Daemon.currentWallet.isWatchOnly ? ' \u00B7 ' + qsTr('watch-only') : '')
        : ''
    // no overflow menu on the Settings tab
    property bool hideOverflow: currentTab == 3

    property alias paymentFlow: _paymentFlow

    // the strip under the Android navigation bar continues the navigation bar of this page
    navigationBarBackgroundColor: m3.surfaceContainer

    function openInvoice(key) {
        return _paymentFlow.openInvoice(key)
    }

    function openRequest(key) {
        return _paymentFlow.openRequest(key)
    }

    function showExport(data, helptext) {
        _paymentFlow.showExport(data, helptext)
    }

    function startSweep() {
        _paymentFlow.startSweep()
    }

    // Android back on a top level tab other than Wallet goes to the Wallet tab first
    function handleBack() {
        if (currentTab != 0) {
            currentTab = 0
            return true
        }
        return false
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: root.currentTab

            HomeTab {
                paymentFlow: _paymentFlow
            }
            ChannelsTab {}
            HistoryTab {}
            SettingsTab {}
        }

        M3NavigationBar {
            Layout.fillWidth: true
            currentIndex: root.currentTab
            onActivated: (index) => { root.currentTab = index }
            model: [
                { icon: Qt.resolvedUrl('../../icons/m3/account_balance_wallet.png'), text: qsTr('Wallet') },
                { icon: Qt.resolvedUrl('../../icons/m3/hub.png'), text: qsTr('Channels') },
                { icon: Qt.resolvedUrl('../../icons/m3/history.png'), text: qsTr('History') },
                { icon: Qt.resolvedUrl('../../icons/m3/settings.png'), text: qsTr('Settings') }
            ]
        }
    }

    PaymentFlow {
        id: _paymentFlow
    }

    Connections {
        target: Daemon
        function onWalletLoaded() {
            root.currentTab = 0  // a newly opened wallet starts on the Wallet tab
        }
    }
}
