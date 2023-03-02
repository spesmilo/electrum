import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

Item {
    id: root

    implicitWidth: balancePane.implicitWidth
    implicitHeight: balancePane.implicitHeight

    property string formattedTotalBalance
    property string formattedTotalBalanceFiat
    property string formattedLightningCanSend
    property string formattedLightningCanSendFiat

    function setBalances() {
        root.formattedTotalBalance = Config.formatSats(Daemon.currentWallet.totalBalance)
        root.formattedLightningCanSend = Config.formatSats(Daemon.currentWallet.lightningCanSend)
        if (Daemon.fx.enabled) {
            root.formattedTotalBalanceFiat = Daemon.fx.fiatValue(Daemon.currentWallet.totalBalance, false)
            root.formattedLightningCanSendFiat = Daemon.fx.fiatValue(Daemon.currentWallet.lightningCanSend, false)
        }
    }

    TextHighlightPane {
        id: balancePane
        leftPadding: constants.paddingXLarge
        rightPadding: constants.paddingXLarge

        GridLayout {
            columns: 3
            opacity: Daemon.currentWallet.synchronizing ? 0 : 1

            Label {
                font.pixelSize: constants.fontSizeXLarge
                text: qsTr('Balance:')
                color: Material.accentColor
            }

            Label {
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
                Layout.preferredHeight: 1
                Layout.preferredWidth: 1
            }
            Label {
                Layout.alignment: Qt.AlignRight
                visible: Daemon.fx.enabled
                font.pixelSize: constants.fontSizeLarge
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
                visible: Daemon.currentWallet.isLightning
                Image {
                    Layout.preferredWidth: constants.iconSizeSmall
                    Layout.preferredHeight: constants.iconSizeSmall
                    source: '../../../icons/lightning.png'
                }
                Label {
                    text: qsTr('Lightning:')
                    font.pixelSize: constants.fontSizeSmall
                    color: Material.accentColor
                }
            }
            Label {
                visible: Daemon.currentWallet.isLightning
                Layout.alignment: Qt.AlignRight
                text: formattedLightningCanSend
                font.family: FixedFont
            }
            Label {
                visible: Daemon.currentWallet.isLightning
                font.pixelSize: constants.fontSizeSmall
                color: Material.accentColor
                text: Config.baseUnit
            }
            Item {
                visible: Daemon.currentWallet.isLightning && Daemon.fx.enabled
                Layout.preferredHeight: 1
                Layout.preferredWidth: 1
            }
            Label {
                Layout.alignment: Qt.AlignRight
                visible: Daemon.currentWallet.isLightning && Daemon.fx.enabled
                font.pixelSize: constants.fontSizeSmall
                color: constants.mutedForeground
                text: formattedLightningCanSendFiat
            }
            Label {
                visible: Daemon.currentWallet.isLightning && Daemon.fx.enabled
                font.pixelSize: constants.fontSizeSmall
                color: constants.mutedForeground
                text: Daemon.fx.fiatCurrency
            }
        }

    }

    Label {
        opacity: Daemon.currentWallet.synchronizing ? 1 : 0
        anchors.centerIn: balancePane
        text: Daemon.currentWallet.synchronizingProgress
        color: Material.accentColor
        font.pixelSize: constants.fontSizeLarge
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
        function onWalletLoaded() { setBalances() }
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

    Component.onCompleted: setBalances()
}
