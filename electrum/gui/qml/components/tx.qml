import QtQuick 2.6

Item {
    id: rootItem
//    height: 800
    Column {
        width: parent.width
//        height: parent.height

        Text {
            text: "Transactions"
        }

        ListView {
            width: parent.width
            height: 200
//            anchors.bottom: rootItem.bottom

            model: Daemon.currentWallet.historyModel
            delegate: Item {
                width: parent.width
                height: line.height
                Row {
                    id: line
                    Rectangle {
                        width: 10
                        height: parent.height
                        color: 'blue'
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
