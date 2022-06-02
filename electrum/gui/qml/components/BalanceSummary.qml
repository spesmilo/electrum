import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

Frame {
    id: root
    height: layout.height
    font.pixelSize: constants.fontSizeMedium

    property string formattedBalance
    property string formattedUnconfirmed
    property string formattedBalanceFiat
    property string formattedUnconfirmedFiat
    property string formattedLightningBalance
    property string formattedLightningBalanceFiat

    function setBalances() {
        root.formattedBalance = Config.formatSats(Daemon.currentWallet.confirmedBalance)
        root.formattedUnconfirmed = Config.formatSats(Daemon.currentWallet.unconfirmedBalance)
        root.formattedLightningBalance = Config.formatSats(Daemon.currentWallet.lightningBalance)
        if (Daemon.fx.enabled) {
            root.formattedBalanceFiat = Daemon.fx.fiatValue(Daemon.currentWallet.confirmedBalance, false)
            root.formattedUnconfirmedFiat = Daemon.fx.fiatValue(Daemon.currentWallet.unconfirmedBalance, false)
            root.formattedLightningBalanceFiat = Daemon.fx.fiatValue(Daemon.currentWallet.lightningBalance, false)
        }
    }

    GridLayout {
        id: layout

        columns: 2
        Label {
            font.pixelSize: constants.fontSizeLarge
            text: qsTr('Balance: ')
        }
        RowLayout {
            Label {
                font.pixelSize: constants.fontSizeLarge
                font.family: FixedFont
                text: formattedBalance
            }
            Label {
                font.pixelSize: constants.fontSizeMedium
                color: Material.accentColor
                text: Config.baseUnit
            }
            Label {
                font.pixelSize: constants.fontSizeMedium
                text: Daemon.fx.enabled
                    ? '(' + root.formattedBalanceFiat + ' ' + Daemon.fx.fiatCurrency + ')'
                    : ''
            }
        }
        Label {
            text: qsTr('Confirmed: ')
            font.pixelSize: constants.fontSizeSmall
        }
        RowLayout {
            Label {
                font.pixelSize: constants.fontSizeSmall
                font.family: FixedFont
                text: formattedBalance
            }
            Label {
                font.pixelSize: constants.fontSizeSmall
                color: Material.accentColor
                text: Config.baseUnit
            }
            Label {
                font.pixelSize: constants.fontSizeSmall
                text: Daemon.fx.enabled
                    ? '(' + root.formattedBalanceFiat + ' ' + Daemon.fx.fiatCurrency + ')'
                    : ''
            }
        }
        Label {
            font.pixelSize: constants.fontSizeSmall
            text: qsTr('Unconfirmed: ')
        }
        RowLayout {
            Label {
                font.pixelSize: constants.fontSizeSmall
                font.family: FixedFont
                text: formattedUnconfirmed
            }
            Label {
                font.pixelSize: constants.fontSizeSmall
                color: Material.accentColor
                text: Config.baseUnit
            }
            Label {
                font.pixelSize: constants.fontSizeSmall
                text: Daemon.fx.enabled
                    ? '(' + root.formattedUnconfirmedFiat + ' ' + Daemon.fx.fiatCurrency + ')'
                    : ''
            }
        }
        Label {
            visible: Daemon.currentWallet.isLightning
            font.pixelSize: constants.fontSizeSmall
            text: qsTr('Lightning: ')
        }
        RowLayout {
            visible: Daemon.currentWallet.isLightning
            Label {
                font.pixelSize: constants.fontSizeSmall
                font.family: FixedFont
                text: formattedLightningBalance
            }
            Label {
                font.pixelSize: constants.fontSizeSmall
                color: Material.accentColor
                text: Config.baseUnit
            }
            Label {
                font.pixelSize: constants.fontSizeSmall
                text: Daemon.fx.enabled
                    ? '(' + root.formattedLightningBalanceFiat + ' ' + Daemon.fx.fiatCurrency + ')'
                    : ''
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
