import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    property Invoice invoice
    property bool payImmediately: false
    property string broadcastTxid

    signal doPay
    signal invoiceAmountChanged

    title: invoice.invoiceType == Invoice.OnchainInvoice ? qsTr('On-chain Invoice') : qsTr('Lightning Invoice')
    iconSource: Qt.resolvedUrl('../../icons/tab_send.png')

    padding: 0

    property bool _canMax: invoice.invoiceType == Invoice.OnchainInvoice

    property Amount _invoice_amount: invoice.amount

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.preferredWidth: parent.width
            Layout.fillHeight: true

            leftMargin: constants.paddingLarge
            rightMargin: constants.paddingLarge

            contentHeight: rootLayout.height
            clip:true
            interactive: height < contentHeight

            GridLayout {
                id: rootLayout
                width: parent.width

                columns: 2

                InfoTextArea {
                    id: helpText
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    Layout.bottomMargin: constants.paddingLarge
                    visible: text
                    text:  invoice.userinfo ? invoice.userinfo : invoice.statusString
                    iconStyle: invoice.status == Invoice.Failed || invoice.status == Invoice.Unknown
                        ? InfoTextArea.IconStyle.Warn
                        : invoice.status == Invoice.Expired
                            ? InfoTextArea.IconStyle.Error
                            : invoice.status == Invoice.Inflight || invoice.status == Invoice.Routing || invoice.status == Invoice.Unconfirmed
                                ? InfoTextArea.IconStyle.Progress
                                : invoice.status == Invoice.Paid
                                    ? InfoTextArea.IconStyle.Done
                                    : invoice.status == Invoice.Unpaid && invoice.expiration > 0
                                        ? invoice.canPay
                                            ? InfoTextArea.IconStyle.Pending
                                            : InfoTextArea.IconStyle.Error
                                        : InfoTextArea.IconStyle.Info
                }

                Label {
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingSmall
                    visible: invoice.invoiceType == Invoice.OnchainInvoice
                    text: qsTr('Address')
                    color: Material.accentColor
                }

                TextHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    visible: invoice.invoiceType == Invoice.OnchainInvoice
                    leftPadding: constants.paddingMedium

                    RowLayout {
                        width: parent.width
                        Label {
                            text: invoice.address
                            font.pixelSize: constants.fontSizeLarge
                            font.family: FixedFont
                            Layout.fillWidth: true
                            wrapMode: Text.Wrap
                        }
                        ToolButton {
                            icon.source: '../../icons/share.png'
                            icon.color: 'transparent'
                            onClicked: {
                                var dialog = app.genericShareDialog.createObject(app, {
                                    title: qsTr('Address'),
                                    text: invoice.address
                                })
                                dialog.open()
                            }
                        }
                    }
                }

                Label {
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingSmall
                    text: qsTr('Description')
                    visible: invoice.message
                    color: Material.accentColor
                }

                TextHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true

                    visible: invoice.message
                    leftPadding: constants.paddingMedium

                    Label {
                        text: invoice.message
                        width: parent.width
                        font.pixelSize: constants.fontSizeXLarge
                        wrapMode: Text.Wrap
                        elide: Text.ElideRight
                    }
                }

                Label {
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingSmall
                    text: qsTr('Amount to send')
                    color: Material.accentColor
                }

                TextHighlightPane {
                    id: amountContainer

                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignHCenter

                    leftPadding: constants.paddingXLarge
                    rightPadding: constants.paddingXLarge

                    property bool editmode: false

                    RowLayout {
                        id: amountLayout
                        width: parent.width

                        GridLayout {
                            visible: !amountContainer.editmode
                            columns: 2

                            Label {
                                Layout.columnSpan: 2
                                Layout.fillWidth: true
                                visible: _invoice_amount.isMax
                                font.pixelSize: constants.fontSizeXLarge
                                font.bold: true
                                text: qsTr('All on-chain funds')
                            }

                            Label {
                                Layout.columnSpan: 2
                                Layout.fillWidth: true
                                visible: _invoice_amount.isEmpty
                                font.pixelSize: constants.fontSizeXLarge
                                color: constants.mutedForeground
                                text: qsTr('not specified')
                            }

                            Label {
                                Layout.alignment: Qt.AlignRight
                                visible: !_invoice_amount.isMax && !_invoice_amount.isEmpty
                                font.pixelSize: constants.fontSizeXLarge
                                font.family: FixedFont
                                font.bold: true
                                text: Config.formatSats(invoice.amount, false)
                            }

                            Label {
                                Layout.fillWidth: true
                                visible: !_invoice_amount.isMax && !_invoice_amount.isEmpty
                                text: Config.baseUnit
                                color: Material.accentColor
                                font.pixelSize: constants.fontSizeXLarge
                            }

                            Label {
                                id: fiatValue
                                Layout.alignment: Qt.AlignRight
                                visible: Daemon.fx.enabled && !_invoice_amount.isMax && !_invoice_amount.isEmpty
                                text: Daemon.fx.fiatValue(invoice.amount, false)
                                font.pixelSize: constants.fontSizeMedium
                                color: constants.mutedForeground
                            }

                            Label {
                                Layout.fillWidth: true
                                visible: Daemon.fx.enabled && !_invoice_amount.isMax && !_invoice_amount.isEmpty
                                text: Daemon.fx.fiatCurrency
                                font.pixelSize: constants.fontSizeMedium
                                color: constants.mutedForeground
                            }

                        }

                        GridLayout {
                            Layout.fillWidth: true
                            visible: amountContainer.editmode
                            enabled: !(invoice.status == Invoice.Expired && _invoice_amount.isEmpty)

                            columns: 3

                            BtcField {
                                id: amountBtc
                                Layout.preferredWidth: amountFontMetrics.advanceWidth('0') * 14 + leftPadding + rightPadding
                                fiatfield: amountFiat
                                readOnly: amountMax.checked
                                color: readOnly
                                    ? Material.accentColor
                                    : Material.foreground
                                onTextAsSatsChanged: {
                                    if (!amountMax.checked)
                                        invoice.amountOverride.satsInt = textAsSats.satsInt
                                }
                                Connections {
                                    target: invoice.amountOverride
                                    function onSatsIntChanged() {
                                        console.log('amountOverride satsIntChanged, sats=' + invoice.amountOverride.satsInt)
                                        if (amountMax.checked)  // amountOverride updated by max amount estimate
                                            amountBtc.text = Config.formatSatsForEditing(invoice.amountOverride.satsInt)
                                    }
                                }
                            }

                            Label {
                                Layout.fillWidth: amountMax.visible ? false : true
                                Layout.columnSpan: amountMax.visible ? 1 : 2

                                text: Config.baseUnit
                                color: Material.accentColor
                            }

                            Switch {
                                id: amountMax
                                Layout.fillWidth: true

                                text: qsTr('Max')
                                visible: _canMax
                                checked: false
                                onCheckedChanged: {
                                    if (activeFocus) {
                                        invoice.amountOverride.isMax = checked
                                        if (checked) {
                                            maxAmountMessage.text = ''
                                            invoice.updateMaxAmount()
                                        }
                                    }
                                }
                            }

                            FiatField {
                                id: amountFiat
                                Layout.preferredWidth: amountFontMetrics.advanceWidth('0') * 14 + leftPadding + rightPadding
                                btcfield: amountBtc
                                visible: Daemon.fx.enabled
                                readOnly: amountMax.checked
                                color: readOnly
                                    ? Material.accentColor
                                    : Material.foreground
                            }

                            Label {
                                Layout.columnSpan: 2
                                visible: Daemon.fx.enabled
                                text: Daemon.fx.fiatCurrency
                                color: Material.accentColor
                            }

                            InfoTextArea {
                                Layout.topMargin: constants.paddingMedium
                                Layout.fillWidth: true
                                Layout.columnSpan: 3
                                id: maxAmountMessage
                                visible: amountMax.checked && text
                                compact: true
                                Connections {
                                    target: invoice
                                    function onMaxAmountMessage(message) {
                                        maxAmountMessage.text = message
                                    }
                                }
                            }
                        }
                    }

                }

                Heading {
                    Layout.columnSpan: 2
                    visible: invoice.invoiceType == Invoice.LightningInvoice
                    text: qsTr('Technical properties')
                }

                Label {
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingSmall
                    visible: invoice.invoiceType == Invoice.LightningInvoice
                    text: qsTr('Remote Pubkey')
                    color: Material.accentColor
                }

                TextHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true

                    visible: invoice.invoiceType == Invoice.LightningInvoice
                    leftPadding: constants.paddingMedium

                    RowLayout {
                        width: parent.width
                        Label {
                            id: pubkeyLabel
                            Layout.fillWidth: true
                            text: 'pubkey' in invoice.lnprops ? invoice.lnprops.pubkey : ''
                            font.family: FixedFont
                            wrapMode: Text.Wrap
                        }
                        ToolButton {
                            icon.source: '../../icons/share.png'
                            icon.color: 'transparent'
                            enabled: pubkeyLabel.text
                            onClicked: {
                                var dialog = app.genericShareDialog.createObject(app,
                                    { title: qsTr('Node public key'), text: invoice.lnprops.pubkey }
                                )
                                dialog.open()
                            }
                        }
                    }
                }

                Label {
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingSmall
                    visible: invoice.invoiceType == Invoice.LightningInvoice
                    text: qsTr('Payment hash')
                    color: Material.accentColor
                }

                TextHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true

                    visible: invoice.invoiceType == Invoice.LightningInvoice
                    leftPadding: constants.paddingMedium

                    RowLayout {
                        width: parent.width
                        Label {
                            id: paymenthashLabel
                            Layout.fillWidth: true
                            text: 'payment_hash' in invoice.lnprops ? invoice.lnprops.payment_hash : ''
                            font.family: FixedFont
                            wrapMode: Text.Wrap
                        }
                        ToolButton {
                            icon.source: '../../icons/share.png'
                            icon.color: 'transparent'
                            enabled: paymenthashLabel.text
                            onClicked: {
                                var dialog = app.genericShareDialog.createObject(app, {
                                    title: qsTr('Payment hash'),
                                    text: invoice.lnprops.payment_hash
                                })
                                dialog.open()
                            }
                        }
                    }
                }

                Label {
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingSmall
                    visible: 'r' in invoice.lnprops && invoice.lnprops.r.length
                    text: qsTr('Routing hints')
                    color: Material.accentColor
                }

                Repeater {
                    visible: 'r' in invoice.lnprops && invoice.lnprops.r.length
                    model: invoice.lnprops.r

                    TextHighlightPane {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true

                        RowLayout {
                            width: parent.width

                            Label {
                                text: modelData.scid
                            }
                            Label {
                                Layout.fillWidth: true
                                text: modelData.node
                                wrapMode: Text.Wrap
                            }
                        }
                    }
                }

                Label {
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingSmall
                    visible: invoice.invoiceType == Invoice.LightningInvoice && invoice.address
                    text: qsTr('Fallback address')
                    color: Material.accentColor
                }

                TextHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    visible: invoice.invoiceType == Invoice.LightningInvoice && invoice.address
                    leftPadding: constants.paddingMedium

                    RowLayout {
                        width: parent.width
                        Label {
                            text: invoice.address
                            font.family: FixedFont
                            Layout.fillWidth: true
                            wrapMode: Text.Wrap
                        }
                        ToolButton {
                            icon.source: '../../icons/share.png'
                            icon.color: 'transparent'
                            onClicked: {
                                var dialog = app.genericShareDialog.createObject(app, {
                                    title: qsTr('Address'),
                                    text: invoice.address
                                })
                                dialog.open()
                            }
                        }
                    }
                }
            }
        }

        ButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Save')
                icon.source: '../../icons/save.png'
                enabled: !invoice.isSaved && invoice.canSave
                onClicked: {
                    if (invoice.amount.isEmpty) {
                        invoice.amountOverride = Config.unitsToSats(amountBtc.text)
                        if (amountMax.checked)
                            invoice.amountOverride.isMax = true
                    }
                    invoice.saveInvoice()
                    app.stack.push(Qt.resolvedUrl('Invoices.qml'))
                    dialog.close()
                }
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Pay...')
                icon.source: '../../icons/confirmed.png'
                enabled: invoice.invoiceType != Invoice.Invalid && invoice.canPay
                onClicked: {
                    if (invoice.amount.isEmpty) {
                        invoice.amountOverride = Config.unitsToSats(amountBtc.text)
                        if (amountMax.checked)
                            invoice.amountOverride.isMax = true
                    }
                    doPay() // only signal here
                }
            }
        }

    }

    Component.onCompleted: {
        if (invoice.amount.isEmpty && !invoice.status == Invoice.Expired) {
            amountContainer.editmode = true
        } else if (invoice.amount.isMax) {
            amountMax.checked = true
        }
        if (payImmediately) {
            if (invoice.canPay) {
                doPay()
            }
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onBroadcastSucceeded(txid) {
            if (dialog.broadcastTxid == txid) {
                // our txid was broadcast successfully, close invoicedialog and show success popup
                dialog.close()
                var successdialog = app.messageDialog.createObject(mainView, {
                    text: qsTr('Payment sent.')
                })
                successdialog.open()
            }
        }
    }

    FontMetrics {
        id: amountFontMetrics
        font: amountBtc.font
    }
}
