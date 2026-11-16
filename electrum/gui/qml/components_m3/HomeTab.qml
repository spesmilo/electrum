import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// Wallet tab: balance card, Receive / Send, network state chips, the last operations ("Recent").
// repeats: components/controls/BalanceSummary.qml:17-24, :34, :131-145, :147-152, :154-187 (balances,
// what is shown while offline or synchronizing, tap -> BalanceDetails, refresh events) @ 4f36c4489;
// components/WalletMainView.qml:260-291 (Receive / Send and their long presses, as the shell placeholder) @ 4f36c4489;
// components/main.qml:214-241 (the network indicators of the classic header: testnet, gossip progress,
// connection / synchronization / lagging server / chain fork / proxy, with the conditions of
// components/controls/OnchainNetworkStatusIndicator.qml:10-14 and LightningNetworkStatusIndicator.qml:7-12)
// @ 4f36c4489; components/History.qml:97-106, :170-176 (empty note, model refresh) @ 4f36c4489.
Item {
    id: root

    property QtObject paymentFlow

    // compact layout of the balance card below 360 dp (folded Fold at a large display size)
    readonly property bool _narrow: width < 360

    // --- balances: strings computed on events, as BalanceSummary (formatSats is a call, not a binding)
    property string formattedConfirmedBalance
    property string formattedTotalBalance
    property string formattedTotalBalanceFiat
    property string formattedLightningBalance

    function setBalances() {
        if (!Daemon.currentWallet)
            return
        root.formattedConfirmedBalance = Config.formatSats(Daemon.currentWallet.confirmedBalance)
        root.formattedTotalBalance = Config.formatSats(Daemon.currentWallet.totalBalance)
        root.formattedLightningBalance = Config.formatSats(Daemon.currentWallet.lightningBalance)
        if (Daemon.fx.enabled) {
            root.formattedTotalBalanceFiat = Daemon.fx.fiatValue(Daemon.currentWallet.totalBalance, false)
        }
    }

    readonly property bool _lightning: Daemon.currentWallet !== null && Daemon.currentWallet.isLightning
    readonly property bool _synchronizing: Daemon.currentWallet !== null && Daemon.currentWallet.synchronizing
    // as BalanceSummary: the figures are hidden while offline or synchronizing
    readonly property bool _showBalance: !_synchronizing && Network.isConnected

    // --- network state, as the classic header indicators
    readonly property bool _connected: Network.isConnected
    readonly property bool _lagging: _connected && Network.isLagging
    readonly property bool _fork: _connected && Network.chaintips > 1
    readonly property bool _proxy: _connected && Network.proxy.enabled
    readonly property int _gossipProgress: Network.gossipInfo.db_channels
        ? (100 * Network.gossipInfo.db_channels / (Network.gossipInfo.unknown_channels + Network.gossipInfo.db_channels))
        : 0

    // --- history model (shared with the History tab), lazy: see HistoryTab.qml
    readonly property QtObject backingModel: Daemon.currentWallet ? Daemon.currentWallet.historyModel : null
    property QtObject _initializedModel: null
    readonly property bool modelReady: backingModel !== null && _initializedModel === backingModel
    readonly property int recentCount: 5

    function initModel() {
        if (!backingModel)
            return
        backingModel.initModel()
        _initializedModel = backingModel
    }

    function showHistoryTab() {
        var walletRoot = app.stack.getRoot()
        if (walletRoot && walletRoot.m3WalletRoot)
            walletRoot.currentTab = 2
    }

    Flickable {
        id: flick
        anchors.fill: parent
        contentHeight: column.implicitHeight + 2 * m3.space16
        clip: true
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: column
            y: m3.space16
            width: Math.min(parent.width, m3.maxContentWidth) - 2 * m3.screenMargin(parent.width)
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: m3.space16

            // ---------------------------------------------------------------- balance card
            M3Card {
                id: balanceCard
                Layout.fillWidth: true
                color: m3.primaryContainer
                contentColor: m3.primaryContainerOn
                radius: m3.radiusXL
                padding: root._narrow ? m3.space16 : m3.space24
                clickable: true
                onClicked: app.stack.push(Qt.resolvedUrl('../components/BalanceDetails.qml'))
                Accessible.role: Accessible.Button
                Accessible.name: qsTranslate('BalanceSummary', 'Balance') + ' ' + root.formattedTotalBalance + ' ' + Config.baseUnit

                ColumnLayout {
                    width: parent.width
                    spacing: m3.space4

                    M3Text {
                        role: 'labelLarge'
                        color: m3.primaryContainerOn
                        text: qsTranslate('BalanceSummary', 'Balance')
                    }

                    // total, shrinking on narrow screens down to a lower limit
                    HomeFitAmount {
                        Layout.fillWidth: true
                        visible: root._showBalance
                        amountText: root.formattedTotalBalance
                        amountRole: 'amountHero'
                        unitRole: 'titleLarge'
                        minimumPixelSize: 24
                        color: m3.primaryContainerOn
                        unitColor: m3.primaryContainerOn
                        spacing: m3.space8
                    }

                    M3Text {
                        visible: root._showBalance && Daemon.fx.enabled
                        role: 'bodyLarge'
                        color: m3.primaryContainerOn
                        text: root.formattedTotalBalanceFiat + ' ' + Daemon.fx.fiatCurrency
                    }

                    // offline / synchronizing: the state instead of the figures, as BalanceSummary
                    RowLayout {
                        visible: !root._showBalance
                        Layout.topMargin: m3.space4
                        spacing: m3.space8
                        M3Icon {
                            source: Qt.resolvedUrl(Network.isConnected
                                ? '../../icons/m3/sync.png'
                                : '../../icons/m3/cloud_off.png')
                            color: m3.primaryContainerOn
                        }
                        M3Text {
                            Layout.fillWidth: true
                            role: 'headlineSmall'
                            color: m3.primaryContainerOn
                            wrapMode: Text.Wrap
                            text: Network.isConnected
                                ? (Daemon.currentWallet ? Daemon.currentWallet.synchronizingProgress : '')
                                : Network.serverStatus
                        }
                    }

                    // on-chain and Lightning parts: Lightning wallets only (as BalanceSummary)
                    GridLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: m3.space12
                        visible: root._showBalance && root._lightning
                        columns: root._narrow ? 1 : 2
                        rowSpacing: m3.space8
                        columnSpacing: m3.space8

                        HomeBalancePart {
                            Layout.fillWidth: true
                            Layout.preferredWidth: 1
                            icon: Qt.resolvedUrl('../../icons/m3/link.png')
                            iconColor: m3.primary
                            title: qsTranslate('BalanceSummary', 'On-chain')
                            amountText: root.formattedConfirmedBalance
                        }
                        HomeBalancePart {
                            Layout.fillWidth: true
                            Layout.preferredWidth: 1
                            icon: Qt.resolvedUrl('../../icons/m3/bolt.png')
                            iconColor: m3.tertiary
                            title: qsTranslate('BalanceSummary', 'Lightning')
                            amountText: root.formattedLightningBalance
                        }
                    }
                }
            }

            // ---------------------------------------------------------------- Receive / Send
            RowLayout {
                Layout.fillWidth: true
                spacing: m3.space12

                M3Button {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    variant: 'tonal'
                    shape: 'large'
                    size: 56
                    icon.source: Qt.resolvedUrl('../../icons/m3/south_west.png')
                    text: qsTr('Receive')
                    onClicked: root.paymentFlow.openReceiveDetailsDialog()
                    onPressAndHold: {
                        Config.userKnowsPressAndHold = true
                        Daemon.currentWallet.deleteExpiredRequests()
                        app.stack.push(Qt.resolvedUrl('../components/ReceiveRequests.qml'))
                        AppController.haptic()
                    }
                }
                M3Button {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    variant: 'filled'
                    shape: 'large'
                    size: 56
                    icon.source: Qt.resolvedUrl('../../icons/m3/north_east.png')
                    text: qsTr('Send')
                    enabled: root.paymentFlow
                        && !root.paymentFlow.invoiceParser.busy
                        && !root.paymentFlow.piResolver.busy
                        && !root.paymentFlow.requestDetails.busy
                    onClicked: root.paymentFlow.openSendDialog()
                    onPressAndHold: {
                        Config.userKnowsPressAndHold = true
                        app.stack.push(Qt.resolvedUrl('../components/Invoices.qml'))
                        AppController.haptic()
                    }
                }
            }

            // ---------------------------------------------------------------- network state chips
            Flow {
                Layout.fillWidth: true
                spacing: m3.space8

                // connection: Disconnected / Connecting / Connected (network.py, translated), synchronizing
                M3Chip {
                    tone: root._connected ? '' : 'error'
                    iconSource: Qt.resolvedUrl(!root._connected
                        ? '../../icons/m3/cloud_off.png'
                        : root._synchronizing
                            ? '../../icons/m3/sync.png'
                            : '../../icons/m3/check_circle.png')
                    text: Network.serverStatus
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/NetworkOverview.qml'))
                }
                M3Chip {
                    visible: root._lagging
                    tone: 'error'
                    iconSource: Qt.resolvedUrl('../../icons/m3/warning.png')
                    text: qsTr('Server is lagging')
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/NetworkOverview.qml'))
                }
                M3Chip {
                    visible: root._fork
                    tone: 'error'
                    iconSource: Qt.resolvedUrl('../../icons/m3/warning.png')
                    text: qsTranslate('NetworkOverview', 'Chain tips:') + ' ' + Network.chaintips
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/NetworkOverview.qml'))
                }
                M3Chip {
                    visible: root._proxy
                    iconSource: Qt.resolvedUrl('../../icons/m3/check.png')
                    text: qsTranslate('NetworkOverview', 'Proxy')
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/NetworkOverview.qml'))
                }
                M3Chip {
                    visible: Network.isTestNet
                    tone: 'tertiary'
                    iconSource: Qt.resolvedUrl('../../icons/m3/info.png')
                    text: Network.networkName
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/NetworkOverview.qml'))
                }
                // Lightning gossip: shown whenever gossip is on (as the classic header icon), with its progress
                M3Chip {
                    visible: Config.useGossip
                    iconSource: Qt.resolvedUrl('../../icons/m3/bolt.png')
                    iconColor: m3.tertiary
                    text: qsTranslate('NetworkOverview', 'Gossip') + ' ' + root._gossipProgress + '%'
                    onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/NetworkOverview.qml'))
                }
            }

            // ---------------------------------------------------------------- recent operations
            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                visible: root.modelReady && root.backingModel.count > 0
                M3Text {
                    Layout.fillWidth: true
                    role: 'titleMedium'
                    text: qsTr('Recent')
                }
                M3Button {
                    variant: 'text'
                    text: qsTr('All')
                    onClicked: root.showHistoryTab()
                }
            }

            M3ListGroup {
                Layout.fillWidth: true
                radius: m3.radiusLI
                visible: root.modelReady && root.backingModel.count > 0

                ListView {
                    id: recentList
                    Layout.fillWidth: true
                    Layout.preferredHeight: Math.min(count, root.recentCount) * 72
                    interactive: false
                    clip: true
                    cacheBuffer: 0
                    model: root.backingModel
                    delegate: M3HistoryDelegate {
                        width: ListView.view.width
                        visible: index < root.recentCount
                    }
                }
            }

            // empty wallet: what to do first. "No transactions" only once the model is initialized and the
            // wallet is up to date (as History.qml); the hint also while offline (a wallet without a
            // server is never up to date, and the balance card says Disconnected), not while a connected
            // wallet is still synchronizing (a restored wallet would flash it).
            M3Card {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                visible: root.modelReady && root.backingModel.count == 0 && (!root._synchronizing || !root._connected)
                color: m3.surfaceContainerLow

                ColumnLayout {
                    width: parent.width
                    spacing: m3.space8
                    M3Icon {
                        Layout.alignment: Qt.AlignHCenter
                        source: Qt.resolvedUrl('../../icons/m3/history.png')
                        size: 32
                        color: m3.surfaceVariantOn
                    }
                    M3Text {
                        Layout.fillWidth: true
                        visible: !root._synchronizing
                        horizontalAlignment: Text.AlignHCenter
                        wrapMode: Text.Wrap
                        role: 'titleMedium'
                        text: qsTranslate('History', 'No transactions in this wallet yet')
                    }
                    M3Text {
                        Layout.fillWidth: true
                        horizontalAlignment: Text.AlignHCenter
                        wrapMode: Text.Wrap
                        role: 'bodyMedium'
                        color: m3.surfaceVariantOn
                        text: qsTr('Receive your first funds: tap Receive.')
                    }
                }
            }
        }
    }

    // one part of the balance (on-chain or Lightning) on the balance card
    component HomeBalancePart: Rectangle {
        id: part
        property url icon
        property color iconColor
        property string title
        property string amountText

        implicitHeight: partLayout.implicitHeight + 2 * m3.space12
        implicitWidth: partLayout.implicitWidth + 2 * m3.space12
        radius: m3.radiusL
        color: m3.surface

        ColumnLayout {
            id: partLayout
            anchors.fill: parent
            anchors.margins: m3.space12
            spacing: 0
            RowLayout {
                spacing: m3.space4
                M3Icon {
                    size: 18
                    source: part.icon
                    color: part.iconColor
                }
                M3Text {
                    role: 'labelMedium'
                    color: m3.surfaceVariantOn
                    text: part.title
                }
            }
            HomeFitAmount {
                Layout.fillWidth: true
                amountText: part.amountText
                amountRole: 'titleMedium'
                unitRole: 'bodySmall'
                minimumPixelSize: 12
                color: m3.surfaceOn
                unitColor: m3.surfaceVariantOn
                spacing: m3.space4
            }
        }
    }

    // an amount and its unit: the font of the amount shrinks to fit the width, down to minimumPixelSize;
    // when even that does not fit, the unit goes to the next line (and the digits wrap, never elide)
    component HomeFitAmount: Flow {
        id: fit
        property string amountText
        property string amountRole
        property string unitRole
        property int minimumPixelSize
        property color color
        property color unitColor

        readonly property var _style: m3.textStyle(amountRole)
        readonly property real _available: width - unitLabel.implicitWidth - spacing
        readonly property int _pixelSize: metrics.advanceWidth > 0 && _available > 0
            ? Math.max(minimumPixelSize, Math.min(_style.size, Math.floor(_style.size * _available / metrics.advanceWidth)))
            : _style.size

        TextMetrics {
            id: metrics
            font.pixelSize: fit._style.size
            font.weight: fit._style.weight
            font.letterSpacing: fit._style.tracking
            text: fit.amountText
        }

        M3Text {
            id: amountLabel
            width: Math.min(implicitWidth, fit.width)
            role: fit.amountRole
            font.pixelSize: fit._pixelSize
            lineHeight: Math.round(fit._style.line * fit._pixelSize / fit._style.size)
            wrapMode: Text.WrapAnywhere
            color: fit.color
            text: fit.amountText
        }
        M3Text {
            id: unitLabel
            height: Math.max(implicitHeight, amountLabel.lineHeight)
            verticalAlignment: Text.AlignBottom
            bottomPadding: Math.round(amountLabel.lineHeight * 0.12)
            role: fit.unitRole
            color: fit.unitColor
            text: Config.baseUnit
        }
    }

    // as BalanceSummary: refresh the balance strings on these events
    Connections {
        target: Config
        function onBaseUnitChanged() { root.setBalances() }
        function onThousandsSeparatorChanged() { root.setBalances() }
    }

    Connections {
        target: Daemon
        function onWalletLoaded() {
            root.setBalances()
            root.initModel()
            flick.contentY = 0
        }
    }

    Connections {
        target: Daemon.fx
        function onEnabledUpdated() { root.setBalances() }
        function onQuotesUpdated() { root.setBalances() }
    }

    Connections {
        target: Daemon.currentWallet
        function onBalanceChanged() { root.setBalances() }
    }

    onVisibleChanged: {
        if (visible)
            root.initModel()
    }

    Component.onCompleted: {
        setBalances()
        initModel()
    }
}
