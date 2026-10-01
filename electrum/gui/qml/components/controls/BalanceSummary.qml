import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

Item {
    id: root

    implicitWidth: balancePane.implicitWidth
    implicitHeight: balancePane.implicitHeight

    property string formattedConfirmedBalance
    property string formattedTotalBalance
    property string formattedTotalBalanceFiat
    property string formattedLightningBalance

    function setBalances() {
        let hide = Config.hideAmounts
        root.formattedConfirmedBalance = Config.formatSats(Daemon.currentWallet.confirmedBalance, false, hide)
        root.formattedTotalBalance = Config.formatSats(Daemon.currentWallet.totalBalance, false, hide)
        root.formattedLightningBalance = Config.formatSats(Daemon.currentWallet.lightningBalance, false, hide)
        if (Daemon.fx.enabled) {
            root.formattedTotalBalanceFiat = Daemon.fx.fiatValue(Daemon.currentWallet.totalBalance, false)
        }
    }

    TextHighlightPane {
        id: balancePane
        leftPadding: constants.paddingXLarge
        rightPadding: constants.paddingXLarge

        Item {
            implicitWidth: Math.max(
                balanceLayout.implicitWidth,
                syncLabel.implicitWidth,
                statusLabel.implicitWidth,
            )
            implicitHeight: balanceLayout.implicitHeight

            GridLayout {
                id: balanceLayout
                anchors.centerIn: parent
                columns: 3
                opacity: Daemon.currentWallet.synchronizing || !Network.isConnected ? 0 : 1

                Label {
                    Layout.row: 0
                    Layout.column: 0
                    font.pixelSize: constants.fontSizeXLarge
                    text: qsTr('Balance') + ':'
                    color: Material.accentColor
                }

                Label {
                    Layout.row: 0
                    Layout.column: 1
                    Layout.alignment: Qt.AlignRight
                    font.pixelSize: constants.fontSizeXLarge
                    font.family: FixedFont
                    text: formattedTotalBalance
                }
                Label {
                    Layout.row: 0
                    Layout.column: 2
                    font.pixelSize: constants.fontSizeXLarge
                    visible: !Config.hideAmounts
                    color: Material.accentColor
                    text: Config.baseUnit
                }

                Item {
                    Layout.row: 1
                    Layout.column: 0
                    visible: Daemon.fx.enabled && !Config.hideAmounts
                    Layout.preferredWidth: 1
                }
                Label {
                    Layout.row: 1
                    Layout.column: 1
                    Layout.alignment: Qt.AlignRight
                    visible: Daemon.fx.enabled && !Config.hideAmounts
                    font.pixelSize: constants.fontSizeLarge
                    font.family: FixedFont
                    color: constants.mutedForeground
                    text: formattedTotalBalanceFiat
                }
                Label {
                    Layout.row: 1
                    Layout.column: 2
                    visible: Daemon.fx.enabled && !Config.hideAmounts
                    font.pixelSize: constants.fontSizeLarge
                    color: constants.mutedForeground
                    text: Daemon.fx.fiatCurrency
                }

                RowLayout {
                    Layout.row: 2
                    Layout.column: 0
                    Layout.alignment: Qt.AlignRight
                    visible: Daemon.currentWallet.isLightning
                    Image {
                        Layout.preferredWidth: constants.iconSizeSmall
                        Layout.preferredHeight: constants.iconSizeSmall
                        source: '../../../icons/lightning.png'
                    }
                    Label {
                        text: qsTr('Lightning') + ':'
                        font.pixelSize: constants.fontSizeSmall
                        color: Material.accentColor
                    }
                }
                Label {
                    Layout.row: 2
                    Layout.column: 1
                    visible: Daemon.currentWallet.isLightning
                    Layout.alignment: Qt.AlignRight
                    text: formattedLightningBalance
                    font.family: FixedFont
                }
                Label {
                    Layout.row: 2
                    Layout.column: 2
                    visible: Daemon.currentWallet.isLightning && !Config.hideAmounts
                    font.pixelSize: constants.fontSizeSmall
                    color: Material.accentColor
                    text: Config.baseUnit
                }

                RowLayout {
                    Layout.row: 3
                    Layout.column: 0
                    Layout.alignment: Qt.AlignRight
                    visible: Daemon.currentWallet.isLightning
                    Image {
                        Layout.preferredWidth: constants.iconSizeSmall
                        Layout.preferredHeight: constants.iconSizeSmall
                        source: '../../../icons/bitcoin.png'
                    }
                    Label {
                        text: qsTr('On-chain') + ':'
                        font.pixelSize: constants.fontSizeSmall
                        color: Material.accentColor
                    }
                }
                Label {
                    id: formattedConfirmedBalanceLabel
                    Layout.row: 3
                    Layout.column: 1
                    visible: Daemon.currentWallet.isLightning
                    Layout.alignment: Qt.AlignRight
                    text: formattedConfirmedBalance
                    font.family: FixedFont
                }
                Label {
                    Layout.row: 3
                    Layout.column: 2
                    visible: Daemon.currentWallet.isLightning && !Config.hideAmounts
                    font.pixelSize: constants.fontSizeSmall
                    color: Material.accentColor
                    text: Config.baseUnit
                }
            }

            Label {
                id: syncLabel
                opacity: Daemon.currentWallet.synchronizing && Network.isConnected ? 1 : 0
                anchors.centerIn: parent
                text: Daemon.currentWallet.synchronizingProgress
                color: Material.accentColor
                font.pixelSize: constants.fontSizeLarge
            }

            Label {
                id: statusLabel
                opacity: !Network.isConnected ? 1 : 0
                anchors.centerIn: parent
                text: Network.serverStatus
                color: Material.accentColor
                font.pixelSize: constants.fontSizeLarge
            }
        }

    }

    MouseArea {
        anchors.fill: parent
        onClicked: {
            app.stack.push(Qt.resolvedUrl('../BalanceDetails.qml'))
        }
        onPressAndHold: {
            Config.hideAmounts = !Config.hideAmounts
            AppController.haptic()
        }
    }

    // instead of all these explicit connections, we should expose
    // formatted balances directly as a property
    Connections {
        target: Config
        function onBaseUnitChanged() { setBalances() }
        function onThousandsSeparatorChanged() { setBalances() }
        function onHideAmountsChanged() { setBalances() }
    }

    Connections {
        target: Daemon
        function onWalletLoaded() {
            setBalances()
        }
    }

    Connections {
        target: Daemon.fx
        function onEnabledUpdated() { setBalances() }
        function onQuotesUpdated() { setBalances() }
    }

    Connections {
        target: Daemon.currentWallet
        function onBalanceChanged() {
            setBalances()
        }
    }

    FontMetrics {
        id: fontMetrics
        font: formattedConfirmedBalanceLabel.font
    }

    Component.onCompleted: setBalances()
}
