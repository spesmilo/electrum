import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0

Pane {
    id: rootItem

    GridLayout {
        width: parent.width
        columns: 4

        BalanceSummary {
            Layout.columnSpan: 4
            //Layout.alignment: Qt.AlignHCenter
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

        Item {
            Layout.fillWidth: true
            Layout.columnSpan: 4

            Row {
                spacing: 10
                anchors.horizontalCenter: parent.horizontalCenter
                Button {
//                    anchors.horizontalCenter: parent.horizontalCenter
                    text: 'Pay'
                    enabled: address.text != '' && amount.text != '' && fee.text != '' // TODO proper validation
                    onClicked: {
                        var i_amount = parseInt(amount.text)
                        if (isNaN(i_amount))
                            return
                        var result = Daemon.currentWallet.send_onchain(address.text, i_amount, undefined, false)
                        if (result)
                            app.stack.pop()
                    }
                }

                Button {
                    text: 'Scan QR Code'
                    Layout.alignment: Qt.AlignHCenter
                    onClicked: app.stack.push(Qt.resolvedUrl('Scan.qml'))
                }
            }
        }
    }

}
