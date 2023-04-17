import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

Item {
    id: root

    implicitWidth: balancePane.implicitWidth
    implicitHeight: balancePane.implicitHeight

    property string formattedConfirmedBalance
    property string formattedTotalBalance
    property string formattedTotalBalanceFiat
    property string formattedLightningBalance

    function setBalances() {
        root.formattedConfirmedBalance = Config.formatSats(Daemon.currentWallet.confirmedBalance)
        root.formattedTotalBalance = Config.formatSats(Daemon.currentWallet.totalBalance)
        root.formattedLightningBalance = Config.formatSats(Daemon.currentWallet.lightningBalance)
        if (Daemon.fx.enabled) {
            root.formattedTotalBalanceFiat = Daemon.fx.fiatValue(Daemon.currentWallet.totalBalance, false)
        }
    }

    TextHighlightPane {
        id: balancePane
        leftPadding: constants.paddingXLarge
        rightPadding: constants.paddingXLarge

        GridLayout {
            id: balanceLayout
            columns: 3
            opacity: Daemon.currentWallet.synchronizing || !Network.is_connected ? 0 : 1

            Label {
                font.pixelSize: constants.fontSizeXLarge
                text: qsTr('Balance') + ':'
                color: Material.accentColor
            }

            Label {
                Layout.alignment: Qt.AlignRight
                font.pixelSize: constants.fontSizeXLarge
                font.family: FixedFont
                text: formattedTotalBalance
            }
            Label {
                font.pixelSize: constants.fontSizeXLarge
                color: Material.accentColor
                text: Config.baseUnit
            }

            Item {
                visible: Daemon.fx.enabled
                Layout.preferredWidth: 1
            }
            Label {
                Layout.alignment: Qt.AlignRight
                visible: Daemon.fx.enabled
                font.pixelSize: constants.fontSizeLarge
                font.family: FixedFont
                color: constants.mutedForeground
                text: formattedTotalBalanceFiat
            }
            Label {
                visible: Daemon.fx.enabled
                font.pixelSize: constants.fontSizeLarge
                color: constants.mutedForeground
                text: Daemon.fx.fiatCurrency
            }

            RowLayout {
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
                visible: Daemon.currentWallet.isLightning
                Layout.alignment: Qt.AlignRight
                text: formattedLightningBalance
                font.family: FixedFont
            }
            Label {
                visible: Daemon.currentWallet.isLightning
                font.pixelSize: constants.fontSizeSmall
                color: Material.accentColor
                text: Config.baseUnit
            }

            RowLayout {
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
                visible: Daemon.currentWallet.isLightning
                Layout.alignment: Qt.AlignRight
                text: formattedConfirmedBalance
                font.family: FixedFont
            }
            Label {
                visible: Daemon.currentWallet.isLightning
                font.pixelSize: constants.fontSizeSmall
                color: Material.accentColor
                text: Config.baseUnit
            }
        }

    }

    Label {
        opacity: Daemon.currentWallet.synchronizing && Network.is_connected ? 1 : 0
        anchors.centerIn: balancePane
        text: Daemon.currentWallet.synchronizingProgress
        color: Material.accentColor
        font.pixelSize: constants.fontSizeLarge
    }

    Label {
        opacity: !Network.is_connected ? 1 : 0
        anchors.centerIn: balancePane
        text: Network.server_status
        color: Material.accentColor
        font.pixelSize: constants.fontSizeLarge
    }

    MouseArea {
        anchors.fill: parent
        onClicked: {
            app.stack.push(Qt.resolvedUrl('../BalanceDetails.qml'))
        }
    }

    // instead of all these explicit connections, we should expose
    // formatted balances directly as a property
    Connections {
        target: Config
        function onBaseUnitChanged() { setBalances() }
        function onThousandsSeparatorChanged() { setBalances() }
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
