import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Pane {
    id: root
    width: parent.width
    height: parent.height
    padding: 0

    property string txid
    property string rawtx

    property alias label: txdetails.label

    signal detailsChanged

    function close() {
        app.stack.pop()
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.topMargin: constants.paddingLarge
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge

            contentHeight: contentLayout.height
            clip: true
            interactive: height < contentHeight

            GridLayout {
                id: contentLayout
                width: parent.width
                columns: 2

                Label {
                    Layout.columnSpan: 2
                    text: qsTr('Transaction Details')
                    font.pixelSize: constants.fontSizeLarge
                    color: Material.accentColor
                }

                Rectangle {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    height: 1
                    color: Material.accentColor
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.columnSpan: 2
                    visible: txdetails.isUnrelated
                    Image {
                        source: '../../icons/warning.png'
                        Layout.preferredWidth: constants.iconSizeSmall
                        Layout.preferredHeight: constants.iconSizeSmall
                    }
                    Label {
                        text: qsTr('Transaction is unrelated to this wallet')
                        color: Material.accentColor
                    }
                }

                Label {
                    Layout.fillWidth: true
                    visible: !txdetails.isUnrelated && txdetails.lnAmount.satsInt == 0
                    text: txdetails.amount.satsInt > 0
                            ? qsTr('Amount received')
                            : qsTr('Amount sent')
                    color: Material.accentColor
                }

                Label {
                    Layout.fillWidth: true
                    visible: !txdetails.isUnrelated && txdetails.lnAmount.satsInt != 0
                    text: txdetails.lnAmount.satsInt > 0
                            ? qsTr('Amount received in channels')
                            : qsTr('Amount withdrawn from channels')
                    color: Material.accentColor
                    wrapMode: Text.Wrap
                }

                RowLayout {
                    visible: !txdetails.isUnrelated
                    Layout.fillWidth: true
                    Label {
                        visible: txdetails.lnAmount.satsInt == 0
                        text: Config.formatSats(txdetails.amount)
                        font.family: FixedFont
                    }
                    Label {
                        visible: txdetails.lnAmount.satsInt != 0
                        text: Config.formatSats(txdetails.lnAmount)
                        font.family: FixedFont
                    }
                    Label {
                        text: Config.baseUnit
                        color: Material.accentColor
                    }
                }

                Item {
                    visible: !txdetails.isUnrelated && Daemon.fx.enabled; Layout.preferredWidth: 1; Layout.preferredHeight: 1
                }

                Label {
                    visible: !txdetails.isUnrelated && Daemon.fx.enabled && txdetails.lnAmount.satsInt == 0
                    text: Daemon.fx.fiatValue(txdetails.amount, false) + ' ' + Daemon.fx.fiatCurrency
                }

                Label {
                    visible: !txdetails.isUnrelated && Daemon.fx.enabled && txdetails.lnAmount.satsInt != 0
                    text: Daemon.fx.fiatValue(txdetails.lnAmount, false) + ' ' + Daemon.fx.fiatCurrency
                }


                Label {
                    Layout.fillWidth: true
                    visible: txdetails.fee.satsInt != 0
                    text: qsTr('Transaction fee')
                    color: Material.accentColor
                }

                RowLayout {
                    Layout.fillWidth: true
                    visible: txdetails.fee.satsInt != 0
                    Label {
                        text: Config.formatSats(txdetails.fee)
                        font.family: FixedFont
                    }
                    Label {
                        Layout.fillWidth: true
                        text: Config.baseUnit
                        color: Material.accentColor
                    }
                    FlatButton {
                        icon.source: '../../icons/warning.png'
                        icon.color: 'transparent'
                        text: qsTr('Bump fee')
                        visible: txdetails.canBump || txdetails.canCpfp
                        onClicked: {
                            if (txdetails.canBump) {
                                var dialog = rbfBumpFeeDialog.createObject(root, { txid: root.txid })
                            } else {
                                var dialog = cpfpBumpFeeDialog.createObject(root, { txid: root.txid })
                            }
                            dialog.open()
                        }
                    }
                }

                Label {
                    text: qsTr('Status')
                    color: Material.accentColor
                }

                Label {
                    Layout.fillWidth: true
                    text: txdetails.status
                }

                Label {
                    text: qsTr('Mempool depth')
                    color: Material.accentColor
                    visible: !txdetails.isMined && txdetails.canBroadcast
                }

                Label {
                    text: txdetails.mempoolDepth
                    visible: !txdetails.isMined && txdetails.canBroadcast
                }

                Label {
                    visible: txdetails.isMined
                    text: qsTr('Date')
                    color: Material.accentColor
                }

                Label {
                    visible: txdetails.isMined
                    text: txdetails.date
                }

                Label {
                    visible: txdetails.isMined
                    text: qsTr('Height')
                    color: Material.accentColor
                }

                Label {
                    visible: txdetails.isMined
                    text: txdetails.height
                }

                Label {
                    visible: txdetails.isMined
                    text: qsTr('TX index')
                    color: Material.accentColor
                }

                Label {
                    visible: txdetails.isMined
                    text: txdetails.txpos
                }

                Label {
                    text: qsTr('Label')
                    Layout.columnSpan: 2
                    color: Material.accentColor
                }

                TextHighlightPane {
                    id: labelContent

                    property bool editmode: false

                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    padding: 0
                    leftPadding: constants.paddingSmall

                    RowLayout {
                        width: parent.width
                        Label {
                            visible: !labelContent.editmode
                            text: txdetails.label
                            wrapMode: Text.Wrap
                            Layout.fillWidth: true
                            font.pixelSize: constants.fontSizeLarge
                        }
                        ToolButton {
                            visible: !labelContent.editmode
                            icon.source: '../../icons/pen.png'
                            icon.color: 'transparent'
                            onClicked: {
                                labelEdit.text = txdetails.label
                                labelContent.editmode = true
                                labelEdit.focus = true
                            }
                        }
                        TextField {
                            id: labelEdit
                            visible: labelContent.editmode
                            text: txdetails.label
                            font.pixelSize: constants.fontSizeLarge
                            Layout.fillWidth: true
                        }
                        ToolButton {
                            visible: labelContent.editmode
                            icon.source: '../../icons/confirmed.png'
                            icon.color: 'transparent'
                            onClicked: {
                                labelContent.editmode = false
                                txdetails.set_label(labelEdit.text)
                            }
                        }
                        ToolButton {
                            visible: labelContent.editmode
                            icon.source: '../../icons/closebutton.png'
                            icon.color: 'transparent'
                            onClicked: labelContent.editmode = false
                        }
                    }
                }

                Label {
                    text: qsTr('Transaction ID')
                    Layout.columnSpan: 2
                    color: Material.accentColor
                }

                TextHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    padding: 0
                    leftPadding: constants.paddingSmall

                    RowLayout {
                        width: parent.width
                        Label {
                            text: txdetails.txid
                            font.pixelSize: constants.fontSizeLarge
                            font.family: FixedFont
                            Layout.fillWidth: true
                            wrapMode: Text.Wrap
                        }
                        ToolButton {
                            icon.source: '../../icons/share.png'
                            icon.color: 'transparent'
                            enabled: txdetails.txid
                            onClicked: {
                                var dialog = app.genericShareDialog.createObject(root,
                                    { title: qsTr('Transaction ID'), text: txdetails.txid }
                                )
                                dialog.open()
                            }
                        }
                    }
                }

                Label {
                    text: qsTr('Outputs')
                    Layout.columnSpan: 2
                    color: Material.accentColor
                }

                Repeater {
                    model: txdetails.outputs
                    delegate: TextHighlightPane {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        padding: 0
                        leftPadding: constants.paddingSmall
                        RowLayout {
                            width: parent.width
                            Label {
                                text: modelData.address
                                Layout.fillWidth: true
                                wrapMode: Text.Wrap
                                font.pixelSize: constants.fontSizeLarge
                                font.family: FixedFont
                                color: modelData.is_mine ? constants.colorMine : Material.foreground
                            }
                            Label {
                                text: Config.formatSats(modelData.value)
                                font.pixelSize: constants.fontSizeMedium
                                font.family: FixedFont
                            }
                            Label {
                                text: Config.baseUnit
                                font.pixelSize: constants.fontSizeMedium
                                color: Material.accentColor
                            }
                        }
                    }
                }
            }

        }

        RowLayout {
            visible: txdetails.canSign || txdetails.canBroadcast
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Sign')
                enabled: txdetails.canSign
                onClicked: txdetails.sign()
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Broadcast')
                enabled: txdetails.canBroadcast
                onClicked: txdetails.broadcast()
            }
        }

        RowLayout {
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Export')
                onClicked: {
                    var dialog = exportTxDialog.createObject(root, { txdetails: txdetails })
                    dialog.open()
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Save')
                visible: txdetails.canSaveAsLocal
                onClicked: txdetails.save()
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Remove')
                visible: txdetails.canRemove
                onClicked: txdetails.removeLocalTx()
            }
        }

        FlatButton {
            Layout.fillWidth: true
            text: qsTr('Cancel Tx')
            visible: txdetails.canCancel
            onClicked: {
                var dialog = rbfCancelDialog.createObject(root, { txid: root.txid })
                dialog.open()
            }
        }

    }

    TxDetails {
        id: txdetails
        wallet: Daemon.currentWallet
        txid: root.txid
        rawtx: root.rawtx
        onLabelChanged: root.detailsChanged()
        onConfirmRemoveLocalTx: {
            var dialog = app.messageDialog.createObject(app, {'text': message, 'yesno': true})
            dialog.yesClicked.connect(function() {
                dialog.close()
                txdetails.removeLocalTx(true)
                txdetails.wallet.historyModel.init_model()
                root.close()
            })
            dialog.open()
        }
        onSaveTxSuccess: {
            var dialog = app.messageDialog.createObject(app, {
                'text': qsTr('Transaction added to wallet history.') + '\n\n' +
                        qsTr('Note: this is an offline transaction, if you want the network to see it, you need to broadcast it.')
            })
            dialog.open()
            root.close()
        }
        onSaveTxError: {
            var dialog = app.messageDialog.createObject(app, {
                'text': message
            })
            dialog.open()
        }
    }

    Component {
        id: rbfBumpFeeDialog
        RbfBumpFeeDialog {
            id: dialog
            rbffeebumper: TxRbfFeeBumper {
                id: rbffeebumper
                wallet: Daemon.currentWallet
                txid: dialog.txid
            }

            onTxaccepted: {
                root.rawtx = rbffeebumper.getNewTx()
                // TODO: sign & send when possible?
            }
            onClosed: destroy()
        }
    }

    Component {
        id: cpfpBumpFeeDialog
        CpfpBumpFeeDialog {
            id: dialog
            cpfpfeebumper: TxCpfpFeeBumper {
                id: cpfpfeebumper
                wallet: Daemon.currentWallet
                txid: dialog.txid
            }

            onTxaccepted: {
                // replaces parent tx with cpfp tx
                root.rawtx = cpfpfeebumper.getNewTx()
                // TODO: sign & send when possible?
            }
            onClosed: destroy()
        }
    }

    Component {
        id: rbfCancelDialog
        RbfCancelDialog {
            id: dialog
            txcanceller: TxCanceller {
                id: txcanceller
                wallet: Daemon.currentWallet
                txid: dialog.txid
            }

            onTxaccepted: {
                root.rawtx = txcanceller.getNewTx()
                // TODO: sign & send when possible?
            }
            onClosed: destroy()
        }
    }

    Component {
        id: exportTxDialog
        ExportTxDialog {
            onClosed: destroy()
        }
    }
}
