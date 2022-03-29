import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

Pane {
    id: rootItem

    GridLayout {
        width: parent.width
        columns: 4

        BalanceSummary {
            Layout.columnSpan: 4
            Layout.alignment: Qt.AlignHCenter
        }

        Label {
            text: qsTr('Recipient')
        }

        TextField {
            id: address
            Layout.columnSpan: 2
            Layout.fillWidth: true
            placeholderText: qsTr('Paste address or invoice')
        }

        ToolButton {
            icon.source: '../../icons/copy.png'
            icon.color: 'transparent'
            icon.height: 16
            icon.width: 16
        }

        Label {
            text: qsTr('Amount')
        }

        TextField {
            id: amount
            placeholderText: qsTr('Amount')
        }

        Label {
            text: Config.baseUnit
            color: Material.accentColor
            Layout.fillWidth: true
        }

        Item { width: 1; height: 1 } // workaround colspan on baseunit messing up row above

        Label {
            text: qsTr('Fee')
        }

        TextField {
            id: fee
            placeholderText: qsTr('sat/vB')
            Layout.columnSpan: 3
        }

        RowLayout {
            Layout.columnSpan: 4
            Layout.alignment: Qt.AlignHCenter
            spacing: 10

            Button {
                text: qsTr('Pay')
                enabled: false // TODO proper validation
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
                text: qsTr('Scan QR Code')
                onClicked: {
                    var page = app.stack.push(Qt.resolvedUrl('Scan.qml'))
                    page.onFound.connect(function() {
                        console.log('got ' + page.scanData)
                        address.text = page.scanData
                    })
                }
            }
        }
    }

    // make clicking the dialog background move the scope away from textedit fields
    // so the keyboard goes away
    MouseArea {
        anchors.fill: parent
        z: -1000
        onClicked: parkFocus.focus = true
        FocusScope { id: parkFocus }
    }

}
