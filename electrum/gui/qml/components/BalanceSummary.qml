import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

Frame {
    id: root

    font.pixelSize: constants.fontSizeMedium

    property string formattedBalance
    property string formattedBalanceFiat
    property string formattedUnconfirmed
    property string formattedUnconfirmedFiat
    property string formattedFrozen
    property string formattedFrozenFiat
    property string formattedLightningBalance
    property string formattedLightningBalanceFiat

    function setBalances() {
        root.formattedBalance = Config.formatSats(Daemon.currentWallet.confirmedBalance)
        root.formattedUnconfirmed = Config.formatSats(Daemon.currentWallet.unconfirmedBalance)
        root.formattedFrozen = Config.formatSats(Daemon.currentWallet.frozenBalance)
        root.formattedLightningBalance = Config.formatSats(Daemon.currentWallet.lightningBalance)
        if (Daemon.fx.enabled) {
            root.formattedBalanceFiat = Daemon.fx.fiatValue(Daemon.currentWallet.confirmedBalance, false)
            root.formattedUnconfirmedFiat = Daemon.fx.fiatValue(Daemon.currentWallet.unconfirmedBalance, false)
            root.formattedFrozenFiat = Daemon.fx.fiatValue(Daemon.currentWallet.frozenBalance, false)
            root.formattedLightningBalanceFiat = Daemon.fx.fiatValue(Daemon.currentWallet.lightningBalance, false)
        }
    }

    GridLayout {
        id: layout

        columns: 2
        Label {
            font.pixelSize: constants.fontSizeXLarge
            text: qsTr('Balance:')
            color: Material.accentColor
            Layout.alignment: Qt.AlignRight | Qt.AlignTop
        }
        ColumnLayout {
            spacing: 0

            RowLayout {
                Label {
                    font.pixelSize: constants.fontSizeXLarge
                    font.family: FixedFont
                    text: formattedBalance
                }
                Label {
                    font.pixelSize: constants.fontSizeXLarge
                    color: Material.accentColor
                    text: Config.baseUnit
                }
            }

            Label {
                visible: Daemon.fx.enabled
                font.pixelSize: constants.fontSizeSmall
                color: constants.mutedForeground
                text: root.formattedBalanceFiat + ' ' + Daemon.fx.fiatCurrency
            }
        }

        Label {
            visible: Daemon.currentWallet.unconfirmedBalance.satsInt > 0
            font.pixelSize: constants.fontSizeLarge
            text: qsTr('Unconfirmed:')
            color: Material.accentColor
            Layout.alignment: Qt.AlignRight | Qt.AlignTop
        }
        ColumnLayout {
            visible: Daemon.currentWallet.unconfirmedBalance.satsInt > 0
            spacing: 0
            RowLayout {
                Label {
                    font.pixelSize: constants.fontSizeLarge
                    font.family: FixedFont
                    text: formattedUnconfirmed
                }
                Label {
                    font.pixelSize: constants.fontSizeLarge
                    color: Material.accentColor
                    text: Config.baseUnit
                }
            }
            Label {
                visible: Daemon.fx.enabled
                font.pixelSize: constants.fontSizeSmall
                color: constants.mutedForeground
                text: root.formattedUnconfirmedFiat + ' ' + Daemon.fx.fiatCurrency
            }
        }

        Label {
            visible: Daemon.currentWallet.frozenBalance.satsInt > 0
            font.pixelSize: constants.fontSizeLarge
            text: qsTr('Frozen:')
            color: Material.accentColor
            Layout.alignment: Qt.AlignRight | Qt.AlignTop
        }
        ColumnLayout {
            visible: Daemon.currentWallet.frozenBalance.satsInt > 0
            spacing: 0

            RowLayout {
                Label {
                    font.pixelSize: constants.fontSizeLarge
                    font.family: FixedFont
                    text: root.formattedFrozen
                }
                Label {
                    font.pixelSize: constants.fontSizeLarge
                    color: Material.accentColor
                    text: Config.baseUnit
                }
            }
            Label {
                visible: Daemon.fx.enabled
                font.pixelSize: constants.fontSizeSmall
                color: constants.mutedForeground
                text: root.formattedFrozenFiat + ' ' + Daemon.fx.fiatCurrency
            }
        }

        Label {
            visible: Daemon.currentWallet.isLightning
            font.pixelSize: constants.fontSizeLarge
            text: qsTr('Lightning:')
            color: Material.accentColor
            Layout.alignment: Qt.AlignRight | Qt.AlignTop
        }
        ColumnLayout {
            visible: Daemon.currentWallet.isLightning
            spacing: 0

            RowLayout {
                Label {
                    font.pixelSize: constants.fontSizeLarge
                    font.family: FixedFont
                    text: formattedLightningBalance
                }
                Label {
                    font.pixelSize: constants.fontSizeLarge
                    color: Material.accentColor
                    text: Config.baseUnit
                }
            }
            Label {
                visible: Daemon.fx.enabled
                font.pixelSize: constants.fontSizeSmall
                color: constants.mutedForeground
                text: root.formattedLightningBalanceFiat + ' ' + Daemon.fx.fiatCurrency
            }
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
