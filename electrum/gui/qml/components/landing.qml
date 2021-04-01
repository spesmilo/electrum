import QtQuick 2.6
import QtQuick.Controls 1.4
import QtQml 2.6

Item {
    Column {
        width: parent.width

        Row {
            Text { text: "Server: " }
            Text { text: Network.server }
        }
        Row {
            Text { text: "Local Height: " }
            Text { text: Network.height }
        }
        Row {
            Text { text: "Status: " }
            Text { text: Network.status }
        }
        Row {
            Text { text: "Wallet: " }
            Text { text: Daemon.walletName }
        }

        EButton {
            text: 'Scan QR Code'
            onClicked: app.stack.push(Qt.resolvedUrl('scan.qml'))
        }

        EButton {
            text: 'Show TXen'
            onClicked: app.stack.push(Qt.resolvedUrl('tx.qml'))
        }

        ListView {
            width: parent.width
            height: 200
            model: Daemon.activeWallets
            delegate: Item {
                width: parent.width

                Row {
                    Rectangle {
                        width: 10
                        height: parent.height
                        color: 'red'
                    }
                    Text {
                        leftPadding: 20
                        text: model.display
                    }
                }
            }
        }

    }

}

