import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

import "controls"

Pane {
    id: rootItem

    GridLayout {
        id: form
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

        RowLayout {
            spacing: 0
            ToolButton {
                icon.source: '../../icons/paste.png'
                icon.height: constants.iconSizeMedium
                icon.width: constants.iconSizeMedium
                onClicked: address.text = AppController.clipboardToText()
            }
            ToolButton {
                icon.source: '../../icons/qrcode.png'
                icon.height: constants.iconSizeMedium
                icon.width: constants.iconSizeMedium
                scale: 1.2
                onClicked: {
                    var page = app.stack.push(Qt.resolvedUrl('Scan.qml'))
                    page.onFound.connect(function() {
                        console.log('got ' + page.invoiceData)
                        address.text = page.invoiceData['address']
                        amount.text = Config.satsToUnits(page.invoiceData['amount'])
                        description.text = page.invoiceData['message']
                    })
                }
            }
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
            property string textAsSats
            onTextChanged: {
                textAsSats = Config.unitsToSats(amount.text)
                if (amountFiat.activeFocus)
                    return
                amountFiat.text = Daemon.fx.fiatValue(amount.textAsSats)
            }

            Connections {
                target: Config
                function onBaseUnitChanged() {
                    amount.text = amount.textAsSats != 0 ? Config.satsToUnits(amount.textAsSats) : ''
                }
            }
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
            onTextChanged: {
                if (amountFiat.activeFocus)
                    amount.text = text == '' ? '' : Config.satsToUnits(Daemon.fx.satoshiValue(amountFiat.text))
            }
        }

        Label {
            visible: Daemon.fx.enabled
            text: Daemon.fx.fiatCurrency
            color: Material.accentColor
            Layout.fillWidth: true
        }

        Item { visible: Daemon.fx.enabled ; height: 1; width: 1 }

        Label {
            text: qsTr('Description')
        }

        TextField {
            id: description
            font.family: FixedFont
            placeholderText: qsTr('Description')
            Layout.columnSpan: 3
            Layout.fillWidth: true
        }

        RowLayout {
            Layout.columnSpan: 4
            Layout.alignment: Qt.AlignHCenter
            spacing: constants.paddingMedium

            Button {
                text: qsTr('Save')
                enabled: false
                onClicked: {
                    console.log('TODO: save')
                }
            }

            Button {
                text: qsTr('Pay now')
                enabled: amount.text != '' && address.text != ''// TODO proper validation
                onClicked: {
                    var f_amount = parseFloat(amount.text)
                    if (isNaN(f_amount))
                        return
                    var sats = Config.unitsToSats(amount.text).toString()
                    var dialog = confirmPaymentDialog.createObject(app, {
                        'address': address.text,
                        'satoshis': sats,
                        'message': description.text
                    })
                    dialog.open()
                }
            }
        }
    }

    Frame {
        verticalPadding: 0
        horizontalPadding: 0

        anchors {
            top: form.bottom
            topMargin: constants.paddingXLarge
            left: parent.left
            right: parent.right
            bottom: parent.bottom
        }

        background: PaneInsetBackground {}

        ColumnLayout {
            spacing: 0
            anchors.fill: parent

            Item {
                Layout.preferredHeight: hitem.height
                Layout.preferredWidth: parent.width
                Rectangle {
                    anchors.fill: parent
                    color: Qt.lighter(Material.background, 1.25)
                }
                RowLayout {
                    id: hitem
                    width: parent.width
                    Label {
                        text: qsTr('Send queue')
                        font.pixelSize: constants.fontSizeXLarge
                    }
                }
            }

            ListView {
                id: listview
                Layout.fillHeight: true
                Layout.fillWidth: true
                clip: true
            }
        }
    }

    Component {
        id: confirmPaymentDialog
        ConfirmPaymentDialog {}
    }

    Connections {
        target: Daemon.fx
        function onQuotesUpdated() {
            amountFiat.text = Daemon.fx.fiatValue(Config.unitsToSats(amount.text))
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
