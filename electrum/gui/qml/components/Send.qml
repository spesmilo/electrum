import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

Pane {
    id: rootItem

    GridLayout {
        width: parent.width
        rowSpacing: constants.paddingSmall
        columnSpacing: constants.paddingSmall
        columns: 4

        BalanceSummary {
            Layout.columnSpan: 4
            Layout.alignment: Qt.AlignHCenter
        }

        Label {
            text: qsTr('Recipient')
        }

        TextArea {
            id: address
            Layout.columnSpan: 2
            Layout.fillWidth: true
            font.family: FixedFont
            wrapMode: Text.Wrap
            placeholderText: qsTr('Paste address or invoice')
        }

        ToolButton {
            icon.source: '../../icons/copy.png'
            icon.color: 'transparent'
            icon.height: constants.iconSizeSmall
            icon.width: constants.iconSizeSmall
        }

        Label {
            text: qsTr('Amount')
        }

        TextField {
            id: amount
            font.family: FixedFont
            placeholderText: qsTr('Amount')
            Layout.preferredWidth: parent.width /2
            inputMethodHints: Qt.ImhPreferNumbers
        }

        Label {
            text: Config.baseUnit
            color: Material.accentColor
            Layout.fillWidth: true
        }

        Item { width: 1; height: 1 }


        Item { width: 1; height: 1; visible: Daemon.fx.enabled }

        TextField {
            id: amountFiat
            visible: Daemon.fx.enabled
            font.family: FixedFont
            Layout.preferredWidth: parent.width /2
            placeholderText: qsTr('Amount')
            inputMethodHints: Qt.ImhPreferNumbers
        }

        Label {
            visible: Daemon.fx.enabled
            text: Daemon.fx.fiatCurrency
            color: Material.accentColor
            Layout.fillWidth: true
        }

        Item { visible: Daemon.fx.enabled ; height: 1; width: 1 }

        Label {
            text: qsTr('Fee')
        }

        TextField {
            id: fee
            font.family: FixedFont
            placeholderText: qsTr('sat/vB')
            Layout.columnSpan: 2
        }

        Item { width: 1; height: 1 }

        RowLayout {
            Layout.columnSpan: 4
            Layout.alignment: Qt.AlignHCenter
            spacing: constants.paddingMedium

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
            amountFiat.text = Daemon.fx.fiatValue(a)
        }
    }
    Connections {
        target: amountFiat
        function onTextChanged() {
            if (amountFiat.activeFocus) {
                amount.text = Daemon.fx.satoshiValue(amountFiat.text)
            }
        }
    }
    Connections {
        target: Daemon.fx
        function onQuotesUpdated() {
            var a = Config.unitsToSats(amount.text)
            amountFiat.text = Daemon.fx.fiatValue(a)
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
