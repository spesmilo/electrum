import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0

Item {
    height: layout.height

    GridLayout {
        id: layout

        columns: 3
        Label {
            Layout.columnSpan: 3
            font.pointSize: 14
            text: 'Balance: ' + Daemon.currentWallet.confirmedBalance //'5.6201 mBTC'
        }
        Label {
            font.pointSize: 8
            text: 'Confirmed: ' + Daemon.currentWallet.confirmedBalance
        }
        Label {
            font.pointSize: 8
            text: 'Unconfirmed: ' + Daemon.currentWallet.unconfirmedBalance
        }
        Label {
            font.pointSize: 8
            text: 'Lightning: ?'
        }
    }

}
