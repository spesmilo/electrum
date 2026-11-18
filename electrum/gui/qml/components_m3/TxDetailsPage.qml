import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// On-chain transaction details of the Material 3 GUI (route app.routes.txDetails, replaces the classic TxDetails).
// repeats: components/TxDetails.qml:10-627 @ e6df7e1c8: the page contract (txid, rawtx, closed, close()), the
// notices and their conditions (error / warning, the state of the transaction, the broadcast result), amount,
// amount in channels, fee, fee rate, status, mempool depth, date, label and its editing, mined at, transaction
// ID, inputs and outputs, the actions and their conditions (Bump fee: RBF or CPFP, Cancel, Sign with the
// "despite warnings" confirmation, Broadcast, Share with its message, Save, Remove), the TxDetails object and
// its handlers, the wallet handlers (saved, save error, broadcast result) and the three fee dialogs with their
// onAccepted handlers. Only the look differs.
// Layout (M2-MAP F-3, F-4): the main actions (Sign, Broadcast, Bump fee, Cancel) are buttons below the content;
// the rare ones (Share = export, Save, Remove) are in the overflow menu of the top app bar (`m3Actions`); the
// details are M3DetailRow rows.
// Strings keep the translation context of the classic file (qsTranslate('TxDetails', ...)).
M3Page {
    id: root

    property string txid
    property string rawtx

    signal closed

    function close() {
        app.stack.pop()
    }

    StackView.onRemoved: {
        closed()
    }

    title: qsTranslate('TxDetails', 'On-chain Transaction')

    readonly property bool _wide: root.width >= 600

    // the conditions of Share..., Save, Remove... (TxDetails.qml:444, 476, 485); the menu items and the overflow
    // button use them (the visible property of an item in a closed menu is false)
    readonly property bool _showShare: !txdetails.error
    readonly property bool _showSave: txdetails.canSaveAsLocal
    readonly property bool _showRemove: txdetails.canRemove

    // TxDetails.qml:439-487 (Share..., Save, Remove...): the overflow menu, shown when one of them is
    property list<Item> m3Actions: [
        M3IconButton {
            visible: root._showShare || root._showSave || root._showRemove
            // the button lives in the top app bar, outside the page: it follows root.enabled itself, so after
            // Remove... (root.enabled = false, TxDetails.qml:497-504) it is disabled with the rest of the page
            enabled: root.enabled
            tooltip: qsTr('More options')
            icon.source: Qt.resolvedUrl('../../icons/m3/more_vert.png')
            onClicked: overflowMenu.open()
        }
    ]

    // the broadcast notice (TxDetails.qml:100-106, set by the wallet handlers below)
    property string _broadcastText
    property int _broadcastIconStyle: M3InfoText.IconStyle.Info

    // TxDetails.qml:446-468
    function share() {
        var msg = ''
        if (txdetails.isComplete) {
            if (!txdetails.isMined && !txdetails.mempoolDepth) // local
                if (txdetails.lockDelay) {
                    msg = qsTranslate('TxDetails', 'This transaction is fully signed, but can only be broadcast after %1 blocks.').arg(txdetails.lockDelay)
                } else {
                    // TODO: iff offline wallet?
                    // TODO: or also if just temporarily offline?
                    msg = qsTranslate('TxDetails', 'This transaction is fully signed, but has not been broadcast yet.')
                }
        } else if (txdetails.wallet.isWatchOnly) {
            msg = qsTranslate('TxDetails', 'This transaction should be signed. Present this QR code to the signing device')
        } else if (txdetails.wallet.isMultisig && txdetails.wallet.walletType != '2fa') {
            if (txdetails.canSign) {
                msg = qsTranslate('TxDetails', 'Note: this wallet can sign, but has not signed this transaction yet')
            } else {
                msg = qsTranslate('TxDetails', 'Transaction is partially signed by this wallet. Present this QR code to the next co-signer')
            }
        }

        app.stack.getRoot().showExport(txdetails.getSerializedTx(), msg)
    }

    // TxDetails.qml:384-391
    function bumpFee() {
        if (txdetails.canBump) {
            var dialog = rbfBumpFeeDialog.createObject(root, { txid: txdetails.txid })
        } else {
            var dialog = cpfpBumpFeeDialog.createObject(root, { txid: txdetails.txid })
        }
        dialog.open()
    }

    // TxDetails.qml:400-403
    function cancelTx() {
        var dialog = rbfCancelDialog.createObject(root, { txid: txdetails.txid })
        dialog.open()
    }

    // TxDetails.qml:413-426
    function sign() {
        if (txdetails.shouldConfirm) {
            var dialog = app.messageDialog.createObject(app, {
                text: qsTranslate('TxDetails', 'Confirm signing transaction despite warnings?'),
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

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            id: flickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentHeight: content.implicitHeight + 2 * m3.space16
            interactive: height < contentHeight
            boundsBehavior: Flickable.StopAtBounds

            ColumnLayout {
                id: content
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
                spacing: m3.space16

                // --- notices (TxDetails.qml:55-106) ---
                M3InfoText {
                    id: warn
                    Layout.fillWidth: true
                    visible: txdetails.error || txdetails.warning
                    text: txdetails.error
                        ? txdetails.error
                        : txdetails.warning
                    iconStyle: txdetails.error
                        ? M3InfoText.IconStyle.Error
                        : M3InfoText.IconStyle.Warn
                }

                M3InfoText {
                    id: txinfo
                    Layout.fillWidth: true
                    visible: (txdetails.isUnrelated || !txdetails.isMined) && !broadcastinfo.visible && !txdetails.error
                    text: txdetails.isUnrelated
                        ? qsTranslate('TxDetails', 'Transaction is unrelated to this wallet.')
                        : txdetails.isRemoved ? qsTranslate('TxDetails', 'This transaction has been replaced or removed and is no longer valid')
                        : txdetails.inMempool
                            ? qsTranslate('TxDetails', 'This transaction is still unconfirmed.') +
                                (txdetails.canBump || txdetails.canCancel
                                    ? txdetails.canCancel
                                        ? '\n' + qsTranslate('TxDetails', 'You can bump its fee to speed up its confirmation, or cancel this transaction.')
                                        : '\n' + qsTranslate('TxDetails', 'You can bump its fee to speed up its confirmation.')
                                    : '')
                            : txdetails.lockDelay
                                ? qsTranslate('TxDetails', 'This transaction is local to your wallet and locked for the next %1 blocks.').arg(txdetails.lockDelay)
                                : txdetails.isComplete
                                    ? qsTranslate('TxDetails', 'This transaction is local to your wallet. It has not been published yet.')
                                    : txdetails.canSign
                                        ? qsTranslate('TxDetails', 'This transaction is not fully signed and can be signed by this wallet.')
                                        : qsTranslate('TxDetails', 'This transaction is not fully signed.') + '\n' +
                                          (txdetails.wallet.isWatchOnly
                                              ? qsTranslate('TxDetails', 'Present this transaction to the signing wallet.')
                                              : qsTranslate('TxDetails', 'Present this transaction to the next cosigner.'))
                    iconStyle: txdetails.isUnrelated || txdetails.isRemoved
                        ? M3InfoText.IconStyle.Warn
                        : M3InfoText.IconStyle.Info
                }

                M3InfoText {
                    id: broadcastinfo
                    Layout.fillWidth: true
                    visible: text
                    text: root._broadcastText
                    iconStyle: root._broadcastIconStyle
                }

                // --- amount (TxDetails.qml:108-125) ---
                ColumnLayout {
                    Layout.fillWidth: true
                    visible: !txdetails.isUnrelated && txdetails.amount.satsInt != 0
                    spacing: m3.space8

                    Rectangle {
                        Layout.alignment: Qt.AlignHCenter
                        implicitWidth: 56
                        implicitHeight: 56
                        radius: 28
                        color: txdetails.amount.satsInt > 0 ? m3.successContainer : m3.primaryContainer
                        M3Icon {
                            anchors.centerIn: parent
                            source: txdetails.amount.satsInt > 0
                                ? Qt.resolvedUrl('../../icons/m3/south_west.png')
                                : Qt.resolvedUrl('../../icons/m3/north_east.png')
                            color: txdetails.amount.satsInt > 0 ? m3.successContainerOn : m3.primaryContainerOn
                        }
                    }

                    M3Text {
                        Layout.fillWidth: true
                        horizontalAlignment: Text.AlignHCenter
                        role: 'labelLarge'
                        color: m3.surfaceVariantOn
                        wrapMode: Text.Wrap
                        text: txdetails.amount.satsInt > 0
                                ? qsTranslate('TxDetails', 'Amount received onchain')
                                : qsTranslate('TxDetails', 'Amount sent onchain')
                    }

                    M3Amount {
                        Layout.alignment: Qt.AlignHCenter
                        amount: txdetails.amount
                        timestamp: txdetails.timestamp
                        role: 'headlineSmall'
                        unitRole: 'titleMedium'
                        fiatRole: 'bodyMedium'
                    }
                }

                // --- details (TxDetails.qml:127-209) ---
                M3ListGroup {
                    Layout.fillWidth: true

                    TxAmountRow {
                        visible: !txdetails.isUnrelated && txdetails.lnAmount.satsInt != 0
                        label: txdetails.lnAmount.satsInt > 0
                                ? qsTranslate('TxDetails', 'Amount received in channels')
                                : qsTranslate('TxDetails', 'Amount withdrawn from channels')
                        amount: txdetails.lnAmount.isEmpty ? txdetails.amount : txdetails.lnAmount
                        timestamp: txdetails.timestamp
                    }

                    TxAmountRow {
                        visible: !txdetails.fee.isEmpty
                        label: qsTranslate('TxDetails', 'Transaction fee')
                        amount: txdetails.fee
                        timestamp: txdetails.timestamp
                    }

                    M3DetailRow {
                        visible: txdetails.feeRateStr != ""
                        label: qsTranslate('TxDetails', 'Transaction fee rate')
                        text: txdetails.feeRateStr
                    }

                    M3DetailRow {
                        visible: !txdetails.error
                        label: qsTranslate('TxDetails', 'Status')
                        text: txdetails.status
                    }

                    M3DetailRow {
                        visible: txdetails.mempoolDepth
                        label: qsTranslate('TxDetails', 'Mempool depth')
                        text: txdetails.mempoolDepth
                    }

                    M3DetailRow {
                        visible: txdetails.isMined
                        label: qsTranslate('TxDetails', 'Date')
                        text: txdetails.date
                    }

                    // --- label (TxDetails.qml:211-271) ---
                    M3DetailRow {
                        id: labelRow
                        visible: !txdetails.error && !txdetails.isUnrelated && !labelEditRow.editmode
                        label: qsTranslate('TxDetails', 'Label')
                        text: txdetails.label
                        actions: [
                            M3IconButton {
                                tooltip: qsTr('Edit')
                                icon.source: Qt.resolvedUrl('../../icons/m3/edit.png')
                                onClicked: {
                                    labelEdit.text = txdetails.label
                                    labelEditRow.editmode = true
                                    labelEdit.field.forceActiveFocus()
                                }
                            }
                        ]
                    }

                    Item {
                        id: labelEditRow
                        property bool editmode: false
                        Layout.fillWidth: true
                        visible: !txdetails.error && !txdetails.isUnrelated && editmode
                        implicitHeight: labelEditLayout.implicitHeight + 2 * m3.space8

                        RowLayout {
                            id: labelEditLayout
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.leftMargin: m3.space16
                            anchors.rightMargin: m3.space4
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 0

                            M3TextField {
                                id: labelEdit
                                Layout.fillWidth: true
                                label: qsTranslate('TxDetails', 'Label')
                                text: txdetails.label
                            }
                            M3IconButton {
                                tooltip: qsTr('Save')
                                icon.source: Qt.resolvedUrl('../../icons/m3/check.png')
                                icon.color: m3.primary
                                onClicked: {
                                    labelEditRow.editmode = false
                                    txdetails.setLabel(labelEdit.text)
                                }
                            }
                            M3IconButton {
                                tooltip: qsTr('Cancel')
                                icon.source: Qt.resolvedUrl('../../icons/m3/close.png')
                                onClicked: labelEditRow.editmode = false
                            }
                        }
                    }
                }

                // --- technical properties (TxDetails.qml:273-324) ---
                M3SectionHeader {
                    Layout.fillWidth: true
                    Layout.bottomMargin: -m3.space8
                    leftPadding: 0
                    visible: !txdetails.error
                    text: qsTranslate('TxDetails', 'Technical properties')
                }

                M3ListGroup {
                    Layout.fillWidth: true
                    visible: !txdetails.error

                    M3DetailRow {
                        visible: txdetails.isMined
                        label: qsTranslate('TxDetails', 'Mined at')
                        text: txdetails.shortId
                    }

                    M3DetailRow {
                        label: qsTranslate('TxDetails', 'Transaction ID')
                        text: txdetails.txid
                        monospace: true
                        shareable: txdetails.txid
                        shareTitle: qsTranslate('TxDetails', 'Transaction ID')
                    }
                }

                // --- inputs and outputs (TxDetails.qml:326-369) ---
                TxIoSection {
                    Layout.fillWidth: true
                    context: 'TxDetails'
                    shown: !txdetails.error
                    inputs: txdetails.inputs
                    outputs: txdetails.outputs
                }
            }
        }

        // --- main actions (TxDetails.qml:374-437): below the content ---
        Rectangle {
            Layout.fillWidth: true
            // the conditions of the buttons below, not their `visible` (that of a child of a hidden item is false)
            visible: txdetails.canSign || txdetails.canBroadcast || txdetails.canBump || txdetails.canCpfp
                || txdetails.canCancel
            implicitHeight: actions.implicitHeight + 2 * m3.space16
            color: m3.surface

            GridLayout {
                id: actions
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
                columns: root._wide ? 4 : 2
                rowSpacing: m3.space8
                columnSpacing: m3.space8

                M3Button {
                    id: signButton
                    Layout.fillWidth: true
                    Layout.columnSpan: actions.columns
                    variant: 'filled'
                    size: 56
                    icon.source: Qt.resolvedUrl('../../icons/m3/draw.png')
                    text: txdetails.shouldConfirm
                        ? qsTranslate('TxDetails', 'Sign...')
                        : qsTranslate('TxDetails', 'Sign')
                    visible: txdetails.canSign
                    onClicked: root.sign()
                }

                M3Button {
                    id: broadcastButton
                    Layout.fillWidth: true
                    Layout.columnSpan: actions.columns
                    variant: 'filled'
                    size: 56
                    icon.source: Qt.resolvedUrl('../../icons/m3/send.png')
                    text: qsTranslate('TxDetails', 'Broadcast')
                    visible: txdetails.canBroadcast
                    enabled: !txdetails.lockDelay
                    onClicked: txdetails.broadcast()
                }

                M3Button {
                    id: feebumpButton
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    Layout.columnSpan: txdetails.canCancel ? 1 : actions.columns
                    variant: txdetails.canSign || txdetails.canBroadcast ? 'tonal' : 'filled'
                    size: 56
                    icon.source: Qt.resolvedUrl('../../icons/m3/speed.png')
                    text: qsTranslate('TxDetails', 'Bump fee...')
                    visible: txdetails.canBump || txdetails.canCpfp
                    onClicked: root.bumpFee()
                }

                M3Button {
                    id: cancelButton
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    Layout.columnSpan: txdetails.canBump || txdetails.canCpfp ? 1 : actions.columns
                    variant: 'outlined'
                    size: 56
                    icon.source: Qt.resolvedUrl('../../icons/m3/cancel.png')
                    text: qsTranslate('TxDetails', 'Cancel Tx...')
                    visible: txdetails.canCancel
                    onClicked: root.cancelTx()
                }
            }
        }
    }

    // --- rare actions (TxDetails.qml:439-487): the overflow menu of the top app bar ---
    M3Menu {
        id: overflowMenu
        x: app.width - overflowMenu.width - m3.space8
        y: app.header ? app.header.height - m3.space8 : 0

        MenuItem {
            id: shareItem
            text: qsTranslate('TxDetails', 'Share...')
            icon.source: Qt.resolvedUrl('../../icons/m3/qr_code.png')
            visible: root._showShare
            height: visible ? implicitHeight : 0
            enabled: !txdetails.isUnrelated && !txdetails.isRemoved
            onTriggered: root.share()
        }
        MenuItem {
            id: saveItem
            text: qsTranslate('TxDetails', 'Save')
            icon.source: Qt.resolvedUrl('../../icons/m3/save.png')
            visible: root._showSave
            height: visible ? implicitHeight : 0
            onTriggered: txdetails.save()
        }
        MenuItem {
            id: removeItem
            text: qsTranslate('TxDetails', 'Remove...')
            icon.source: Qt.resolvedUrl('../../icons/m3/delete.png')
            visible: root._showRemove
            height: visible ? implicitHeight : 0
            onTriggered: txdetails.removeLocalTx()
        }
    }

    TxDetails {
        id: txdetails
        wallet: Daemon.currentWallet
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
                title: qsTranslate('TxDetails', 'Transaction added to wallet history.'),
                text: qsTranslate('TxDetails', 'Note: this is an offline transaction, if you want the network to see it, you need to broadcast it.')
            })
            dialog.open()
            root.close()
        }
        function onSaveTxError(txid, code, message) {
            if (txid != txdetails.txid)
                return
            var dialog = app.messageDialog.createObject(app, {
                title: qsTranslate('TxDetails', 'Error'),
                iconSource: Qt.resolvedUrl('../../icons/m3/warning.png'),
                text: message
            })
            dialog.open()
        }
        function onBroadcastSucceeded() {
            root._broadcastText = qsTranslate('TxDetails', 'Transaction was broadcast successfully')
            root._broadcastIconStyle = M3InfoText.IconStyle.Info
        }
        function onBroadcastFailed(txid, code, message) {
            root._broadcastText = qsTranslate('TxDetails', 'Broadcast of transaction failed')
            root._broadcastIconStyle = M3InfoText.IconStyle.Warn
        }
    }

    Component {
        id: rbfBumpFeeDialog
        BumpFeeDialog {
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
                        title: qsTranslate('TxDetails', 'Transaction fee updated.'),
                        text: qsTranslate('TxDetails', 'You still need to sign and broadcast this transaction.')
                    })
                    dialog.open()
                }
            }
            onClosed: destroy()
        }
    }

    Component {
        id: cpfpBumpFeeDialog
        CpfpDialog {
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
                        title: qsTranslate('TxDetails', 'CPFP fee bump transaction created.'),
                        text: qsTranslate('TxDetails', 'You still need to sign and broadcast this transaction.')
                    })
                    dialog.open()
                }
            }
            onClosed: destroy()
        }
    }

    Component {
        id: rbfCancelDialog
        CancelTxDialog {
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
                        title: qsTranslate('TxDetails', 'Cancel transaction created.'),
                        text: qsTranslate('TxDetails', 'You still need to sign and broadcast this transaction.')
                    })
                    dialog.open()
                }
            }
            onClosed: destroy()
        }
    }
}
