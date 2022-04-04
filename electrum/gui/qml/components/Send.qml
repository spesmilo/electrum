import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

Pane {
    id: rootItem

    GridLayout {
        width: parent.width
        columns: 6

        BalanceSummary {
            Layout.columnSpan: 6
            Layout.alignment: Qt.AlignHCenter
        }

        Label {
            text: qsTr('Recipient')
        }

        TextField {
            id: address
            Layout.columnSpan: 4
            Layout.fillWidth: true
            font.family: FixedFont
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
            font.family: FixedFont
            placeholderText: qsTr('Amount')
            inputMethodHints: Qt.ImhPreferNumbers
        }

        Label {
            text: Config.baseUnit + '  ' // add spaces for easy right margin
            color: Material.accentColor
        }

        TextField {
            id: amountFiat
            visible: Config.fiatCurrency != ''
            font.family: FixedFont
            placeholderText: qsTr('Amount')
            inputMethodHints: Qt.ImhPreferNumbers
        }

        Label {
            visible: Config.fiatCurrency != ''
            text: Config.fiatCurrency
            color: Material.accentColor
        }

        Item { visible: Config.fiatCurrency == ''; height: 1; Layout.columnSpan: 2; Layout.fillWidth: true }

        Item { width: 1; height: 1 } // workaround colspan on baseunit messing up row above

        Label {
            text: qsTr('Fee')
        }

        TextField {
            id: fee
            font.family: FixedFont
            placeholderText: qsTr('sat/vB')
            Layout.columnSpan: 5
        }

        RowLayout {
            Layout.columnSpan: 6
            Layout.alignment: Qt.AlignHCenter
            spacing: 10

            Button {
                text: qsTr('Pay')
                enabled: amount.text != '' && address.text != ''// TODO proper validation
                onClicked: {
                    var f_amount = parseFloat(amount.text)
                    if (isNaN(f_amount))
                        return
                    var sats = Config.unitsToSats(f_amount)
                    var result = Daemon.currentWallet.send_onchain(address.text, sats, undefined, false)
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

    Connections {
        target: amount
        function onTextChanged() {
            if (amountFiat.activeFocus)
                return
            var a = Config.unitsToSats(amount.text)
            amountFiat.text = Daemon.fiatValue(a)
        }
    }
    Connections {
        target: amountFiat
        function onTextChanged() {
            if (amountFiat.activeFocus) {
                amount.text = Daemon.satoshiValue(amountFiat.text)
            }
        }
    }
    Connections {
        target: Network
        function onFiatUpdated() {
            var a = Config.unitsToSats(amount.text)
            amountFiat.text = Daemon.fiatValue(a)
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
