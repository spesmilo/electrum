import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

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
    signal closed

    function close() {
        app.stack.pop()
    }

    StackView.onRemoved: {
        closed()
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true

            contentHeight: flickableRoot.height
            clip: true
            interactive: height < contentHeight

            Pane {
                id: flickableRoot
                width: parent.width
                padding: constants.paddingLarge

                GridLayout {
                    width: parent.width
                    columns: 2

                    Heading {
                        Layout.columnSpan: 2
                        text: qsTr('On-chain Transaction')
                    }

                    InfoTextArea {
                        id: warn
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        Layout.bottomMargin: constants.paddingLarge
                        visible: txdetails.warning
                        text: txdetails.warning
                        iconStyle: InfoTextArea.IconStyle.Warn
                    }

                    InfoTextArea {
                        id: txinfo
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        Layout.bottomMargin: constants.paddingLarge
                        visible: (txdetails.isUnrelated || !txdetails.isMined) && !broadcastinfo.visible
                        text: txdetails.isUnrelated
                            ? qsTr('Transaction is unrelated to this wallet.')
                            : txdetails.isRemoved ? qsTr('This transaction has been replaced or removed and is no longer valid')
                            : txdetails.inMempool
                                ? qsTr('This transaction is still unconfirmed.') +
                                    (txdetails.canBump || txdetails.canCancel
                                        ? txdetails.canCancel
                                            ? '\n' + qsTr('You can bump its fee to speed up its confirmation, or cancel this transaction.')
                                            : '\n' + qsTr('You can bump its fee to speed up its confirmation.')
                                        : '')
                                : txdetails.lockDelay
                                    ? qsTr('This transaction is local to your wallet and locked for the next %1 blocks.').arg(txdetails.lockDelay)
                                    : txdetails.isComplete
                                        ? qsTr('This transaction is local to your wallet. It has not been published yet.')
                                        : txdetails.canSign
                                            ? qsTr('This transaction is not fully signed and can be signed by this wallet.')
                                            : qsTr('This transaction is not fully signed.') + '\n' +
                                              (txdetails.wallet.isWatchOnly
                                                  ? qsTr('Present this transaction to the signing wallet.')
                                                  : qsTr('Present this transaction to the next cosigner.'))
                        iconStyle: txdetails.isUnrelated || txdetails.isRemoved
                            ? InfoTextArea.IconStyle.Warn
                            : InfoTextArea.IconStyle.Info
                    }

                    InfoTextArea {
                        id: broadcastinfo
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        Layout.bottomMargin: constants.paddingLarge
                        visible: text
                    }

                    Label {
                        Layout.preferredWidth: 1
                        Layout.fillWidth: true
                        visible: !txdetails.isUnrelated && txdetails.amount.satsInt != 0
                        text: txdetails.amount.satsInt > 0
                                ? qsTr('Amount received onchain')
                                : qsTr('Amount sent onchain')
                        color: Material.accentColor
                        wrapMode: Text.Wrap
                    }

                    FormattedAmount {
                        Layout.preferredWidth: 1
                        Layout.fillWidth: true
                        visible: !txdetails.isUnrelated && txdetails.amount.satsInt != 0
                        amount: txdetails.amount
                        timestamp: txdetails.timestamp
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

                    FormattedAmount {
                        visible: !txdetails.isUnrelated && txdetails.lnAmount.satsInt != 0
                        Layout.preferredWidth: 1
                        Layout.fillWidth: true
                        amount: txdetails.lnAmount.isEmpty ? txdetails.amount : txdetails.lnAmount
                        timestamp: txdetails.timestamp
                    }

                    Label {
                        visible: !txdetails.fee.isEmpty
                        text: qsTr('Transaction fee')
                        color: Material.accentColor
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        visible: !txdetails.fee.isEmpty
                        FormattedAmount {
                            Layout.fillWidth: true
                            amount: txdetails.fee
                            timestamp: txdetails.timestamp
                        }
                    }

                    Label {
                        Layout.preferredWidth: 1
                        Layout.fillWidth: true
                        visible: txdetails.feeRateStr != ""
                        text: qsTr('Transaction fee rate')
                        color: Material.accentColor
                        wrapMode: Text.Wrap
                    }

                    Label {
                        Layout.fillWidth: true
                        visible: txdetails.feeRateStr != ""
                        text: txdetails.feeRateStr
                    }

                    Label {
                        Layout.fillWidth: true
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
                        visible: txdetails.mempoolDepth
                    }

                    Label {
                        text: txdetails.mempoolDepth
                        visible: txdetails.mempoolDepth
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
                        Layout.columnSpan: 2
                        Layout.topMargin: constants.paddingSmall
                        visible: !txdetails.isUnrelated
                        text: qsTr('Label')
                        color: Material.accentColor
                    }

                    TextHighlightPane {
                        id: labelContent

                        property bool editmode: false

                        Layout.columnSpan: 2
                        Layout.fillWidth: true

                        visible: !txdetails.isUnrelated

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
                                    txdetails.setLabel(labelEdit.text)
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

                    Heading {
                        Layout.columnSpan: 2
                        text: qsTr('Technical properties')
                    }

                    Label {
                        visible: txdetails.isMined
                        text: qsTr('Mined at')
                        color: Material.accentColor
                    }

                    Label {
                        visible: txdetails.isMined
                        text: txdetails.shortId
                    }

                    Label {
                        Layout.columnSpan: 2
                        Layout.topMargin: constants.paddingSmall
                        text: qsTr('Transaction ID')
                        color: Material.accentColor
                    }

                    TextHighlightPane {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true

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

                    ToggleLabel {
                        id: inputs_label
                        Layout.columnSpan: 2
                        Layout.topMargin: constants.paddingMedium

                        labelText: qsTr('Inputs (%1)').arg(txdetails.inputs.length)
                        color: Material.accentColor
                    }

                    Repeater {
                        model: inputs_label.collapsed
                            ? undefined
                            : txdetails.inputs
                        delegate: TxInput {
                            Layout.columnSpan: 2
                            Layout.fillWidth: true

                            idx: index
                            model: modelData
                        }
                    }

                    ToggleLabel {
                        id: outputs_label
                        Layout.columnSpan: 2
                        Layout.topMargin: constants.paddingMedium

                        labelText: qsTr('Outputs (%1)').arg(txdetails.outputs.length)
                        color: Material.accentColor
                    }

                    Repeater {
                        model: outputs_label.collapsed
                            ? undefined
                            : txdetails.outputs
                        delegate: TxOutput {
                            Layout.columnSpan: 2
                            Layout.fillWidth: true

                            idx: index
                            model: modelData
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
                id: feebumpButton
                icon.source: '../../icons/add.png'
                text: qsTr('Bump fee...')
                visible: txdetails.canBump || txdetails.canCpfp
                onClicked: {
                    if (txdetails.canBump) {
                        var dialog = rbfBumpFeeDialog.createObject(root, { txid: txdetails.txid })
                    } else {
                        var dialog = cpfpBumpFeeDialog.createObject(root, { txid: txdetails.txid })
                    }
                    dialog.open()
                }
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                id: cancelButton
                icon.source: '../../icons/closebutton.png'
                text: qsTr('Cancel Tx...')
                visible: txdetails.canCancel
                onClicked: {
                    var dialog = rbfCancelDialog.createObject(root, { txid: txdetails.txid })
                    dialog.open()
                }
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/key.png'
                text: txdetails.shouldConfirm
                    ? qsTr('Sign...')
                    : qsTr('Sign')
                visible: txdetails.canSign
                onClicked: {
                    if (txdetails.shouldConfirm) {
                        var dialog = app.messageDialog.createObject(app, {
                            text: qsTr('Confirm signing transaction despite warnings?'),
                            yesno: true
                        })
                        dialog.accepted.connect(function() {
                            txdetails.sign()
                        })
                        dialog.open()
                    } else {
                        txdetails.sign()
                    }
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/tab_send.png'
                text: qsTr('Broadcast')
                visible: txdetails.canBroadcast
                enabled: !txdetails.lockDelay
                onClicked: txdetails.broadcast()
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/qrcode_white.png'
                text: qsTr('Share...')
                enabled: !txdetails.isUnrelated && !txdetails.isRemoved
                onClicked: {
                    var msg = ''
                    if (txdetails.isComplete) {
                        if (!txdetails.isMined && !txdetails.mempoolDepth) // local
                            if (txdetails.lockDelay) {
                                msg = qsTr('This transaction is fully signed, but can only be broadcast after %1 blocks.').arg(txdetails.lockDelay)
                            } else {
                                // TODO: iff offline wallet?
                                // TODO: or also if just temporarily offline?
                                msg = qsTr('This transaction is fully signed, but has not been broadcast yet.')
                            }
                    } else if (txdetails.wallet.isWatchOnly) {
                        msg = qsTr('This transaction should be signed. Present this QR code to the signing device')
                    } else if (txdetails.wallet.isMultisig && txdetails.wallet.walletType != '2fa') {
                        if (txdetails.canSign) {
                            msg = qsTr('Note: this wallet can sign, but has not signed this transaction yet')
                        } else {
                            msg = qsTr('Transaction is partially signed by this wallet. Present this QR code to the next co-signer')
                        }
                    }

                    app.stack.getRoot().showExport(txdetails.getSerializedTx(), msg)
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/save.png'
                text: qsTr('Save')
                visible: txdetails.canSaveAsLocal
                onClicked: txdetails.save()
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/delete.png'
                text: qsTr('Remove...')
                visible: txdetails.canRemove
                onClicked: txdetails.removeLocalTx()
            }

        }

    }

    TxDetails {
        id: txdetails
        wallet: Daemon.currentWallet
        onLabelChanged: root.detailsChanged()
        onConfirmRemoveLocalTx: (message) => {
            var dialog = app.messageDialog.createObject(app, { text: message, yesno: true })
            dialog.accepted.connect(function() {
                txdetails.removeLocalTx(true)
                root.enabled = false
            })
            dialog.open()
        }
        Component.onCompleted: {
            if (root.txid) {
                txdetails.txid = root.txid
            } else if (root.rawtx) {
                txdetails.rawtx = root.rawtx
            }
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onSaveTxSuccess(txid) {
            if (txid != txdetails.txid)
                return
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Transaction added to wallet history.'),
                text: qsTr('Note: this is an offline transaction, if you want the network to see it, you need to broadcast it.')
            })
            dialog.open()
            root.close()
        }
        function onSaveTxError(txid, code, message) {
            if (txid != txdetails.txid)
                return
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            dialog.open()
        }
        function onBroadcastSucceeded() {
            broadcastinfo.text = qsTr('Transaction was broadcast successfully')
            broadcastinfo.iconStyle = InfoTextArea.IconStyle.Info
        }
        function onBroadcastFailed(txid, code, message) {
            broadcastinfo.text = qsTr('Broadcast of transaction failed')
            broadcastinfo.iconStyle = InfoTextArea.IconStyle.Warn
        }
    }

    Component {
        id: rbfBumpFeeDialog
        RbfBumpFeeDialog {
            id: dialog
            required property string txid
            rbffeebumper: TxRbfFeeBumper {
                id: rbffeebumper
                wallet: Daemon.currentWallet
                txid: dialog.txid
            }
            onAccepted: {
                txdetails.rawtx = rbffeebumper.getNewTx()
                if (txdetails.wallet.canSignWithoutCosigner) {
                    txdetails.signAndBroadcast()
                } else {
                    var dialog = app.messageDialog.createObject(app, {
                        title: qsTr('Transaction fee updated.'),
                        text: qsTr('You still need to sign and broadcast this transaction.')
                    })
                    dialog.open()
                }
            }
            onClosed: destroy()
        }
    }

    Component {
        id: cpfpBumpFeeDialog
        CpfpBumpFeeDialog {
            id: dialog
            required property string txid
            cpfpfeebumper: TxCpfpFeeBumper {
                id: cpfpfeebumper
                wallet: Daemon.currentWallet
                txid: dialog.txid
            }

            onAccepted: {
                // replaces parent tx with cpfp tx
                txdetails.rawtx = cpfpfeebumper.getNewTx()
                if (txdetails.wallet.canSignWithoutCosigner) {
                    txdetails.signAndBroadcast()
                } else {
                    var dialog = app.messageDialog.createObject(app, {
                        title: qsTr('CPFP fee bump transaction created.'),
                        text: qsTr('You still need to sign and broadcast this transaction.')
                    })
                    dialog.open()
                }
            }
            onClosed: destroy()
        }
    }

    Component {
        id: rbfCancelDialog
        RbfCancelDialog {
            id: dialog
            required property string txid
            txcanceller: TxCanceller {
                id: txcanceller
                wallet: Daemon.currentWallet
                txid: dialog.txid
            }

            onAccepted: {
                txdetails.rawtx = txcanceller.getNewTx()
                if (txdetails.wallet.canSignWithoutCosigner) {
                    txdetails.signAndBroadcast()
                } else {
                    var dialog = app.messageDialog.createObject(app, {
                        title: qsTr('Cancel transaction created.'),
                        text: qsTr('You still need to sign and broadcast this transaction.')
                    })
                    dialog.open()
                }
            }
            onClosed: destroy()
        }
    }

}
