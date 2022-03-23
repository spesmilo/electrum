import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0

Frame {
    id: root
    height: layout.height

    property string formattedBalance
    property string formattedUnconfirmed

    function setBalances() {
        root.formattedBalance = Config.formatSats(Daemon.currentWallet.confirmedBalance, true)
        root.formattedUnconfirmed = Config.formatSats(Daemon.currentWallet.unconfirmedBalance, true)
    }

    GridLayout {
        id: layout

        columns: 3
        Label {
            id: balance
            Layout.columnSpan: 3
            font.pixelSize: constants.fontSizeLarge
            text: 'Balance: ' + formattedBalance
        }
        Label {
            id: confirmed
            font.pixelSize: constants.fontSizeMedium
            text: 'Confirmed: ' + formattedBalance
        }
        Label {
            id: unconfirmed
            font.pixelSize: constants.fontSizeMedium
            text: 'Unconfirmed: ' + formattedUnconfirmed
        }
        Label {
            id: lightning
            font.pixelSize: constants.fontSizeSmall
            text: 'Lightning: ?'
        }
    }

    Connections {
        target: Config
        function onBaseUnitChanged() { setBalances() }
        function onThousandsSeparatorChanged() { setBalances() }
    }

    Connections {
        target: Daemon
        function onWalletLoaded() { setBalances() }
    }

    Component.onCompleted: setBalances()
}
