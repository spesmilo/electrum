import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0

Item {
    id: rootItem

    property string title: 'Send'

    GridLayout {
        width: rootItem.width - 12
        anchors.horizontalCenter: parent.horizontalCenter
        columns: 4

        Label {
            Layout.columnSpan: 4
            Layout.alignment: Qt.AlignHCenter
            text: "Current Balance: 0 mBTC"
        }

        Label {
            text: "Recipient"
        }

        TextField {
            id: address
            Layout.columnSpan: 3
            placeholderText: 'Paste address or invoice'
            Layout.fillWidth: true
        }

        Label {
            text: "Amount"
        }

        TextField {
            id: amount
            placeholderText: 'Amount'
        }

        Label {
            text: "Fee"
        }

        TextField {
            id: fee
            placeholderText: 'sat/vB'
        }

        Column {
            Layout.fillWidth: true
            Layout.columnSpan: 4

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: 'Pay'
                onClicked: {
                    var i_amount = parseInt(amount.text)
                    if (isNaN(i_amount))
                        return
                    var result = Daemon.currentWallet.send_onchain(address.text, i_amount, undefined, false)
                    if (result)
                        app.stack.pop()
                }
            }
        }
    }

}
