import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// "Open Lightning Channel" of the Material 3 GUI: the type of the app.openChannelDialog factory (M2-MAP F-1: a
// full-screen dialog, created by the factory without properties from the Channels tab and from BalanceDetailsPage,
// F-12).
// repeats: components/OpenChannelDialog.qml:10-334 @ e6df7e1c8: the two recoverability warnings and their
// conditions (lightningHasDeterministicNodeId, seedType, Config.useRecoverableChannels); with gossip the node
// URI field (written to channelopener.connectStr while edited and when it loses the focus), Paste (the clipboard
// validated by validateConnectString, else "Invalid node-id or connect string") and Scan (app.scanDialog with its
// hint, the same validation, the scanner closed); without gossip the choice of a trampoline node, a random one
// preselected; the amount (written to channelopener.amount unless Max) with Max (isMax + updateMaxAmount(), the
// field read-only and filled from the max estimate); the warning of the opener; "Open Channel..." enabled when
// valid -> openChannel(); the ChannelOpener object and all its handlers: authRequired, validationError
// ('invalid_nodeid'), conflictingBackup (yes -> openChannel(true)), finalizerChanged -> ConfirmTxDialog (the
// Material 3 one, "Channel capacity" / "Open Channel", accepted -> signAndSend()), channelOpening /
// channelOpenError / channelOpenSuccess -> app.channelOpenProgressDialog (the history refreshed for an incomplete
// funding transaction, the channel backup handed over when it has no on-chain backup, this dialog closed).
// Differences: Material 3 look (the top bar of M3FullScreenDialog, X closes; M3TextArea with Paste and Scan as icon
// buttons; the trampoline node as an M3SelectRow; M3AmountField with the Max switch; "Open Channel..." in the bar at
// the bottom). Max is written on onToggled (user change only, as the classic onCheckedChanged + activeFocus); the
// trampoline node is written on the user's choice (the classic onCurrentValueChanged + activeFocus) and at start.
// New Material 3 calls pass the Material 3 warning glyph (zone probe: M3 MessageDialog takes it as is).
// Strings keep the translation context of the classic file (qsTranslate('OpenChannelDialog', ...)).
M3FullScreenDialog {
    id: root

    title: qsTranslate('OpenChannelDialog', 'Open Lightning Channel')
    iconSource: Qt.resolvedUrl('../../icons/m3/bolt.png')

    // the trampoline node shown by the select row (OpenChannelDialog.qml:145-161)
    property string _trampolineNode

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

                M3InfoText {
                    Layout.fillWidth: true
                    visible: !Daemon.currentWallet.lightningHasDeterministicNodeId
                    iconStyle: M3InfoText.IconStyle.Warn
                    text: Daemon.currentWallet.seedType == 'segwit'
                        ? [ qsTranslate('OpenChannelDialog', 'Your channels cannot be recovered from seed, because they were created with an old version of Electrum.'), ' ',
                            qsTranslate('OpenChannelDialog', 'This means that you must save a backup of your wallet every time you create a new channel.'),
                            '\n\n',
                            qsTranslate('OpenChannelDialog', 'If you want this wallet to have recoverable channels, you must close your existing channels and restore this wallet from seed.')
                          ].join('')
                        : [ qsTranslate('OpenChannelDialog', 'Your channels cannot be recovered from seed.'), ' ',
                            qsTranslate('OpenChannelDialog', 'This means that you must save a backup of your wallet every time you create a new channel.'),
                            '\n\n',
                            qsTranslate('OpenChannelDialog', 'If you want to have recoverable channels, you must create a new wallet with an Electrum seed')
                          ].join('')
                }

                M3InfoText {
                    Layout.fillWidth: true
                    visible: Daemon.currentWallet.lightningHasDeterministicNodeId && !Config.useRecoverableChannels
                    iconStyle: M3InfoText.IconStyle.Warn
                    text: [ qsTranslate('OpenChannelDialog', 'You currently have recoverable channels setting disabled.'),
                            qsTranslate('OpenChannelDialog', 'This means your channels cannot be recovered from seed.')
                          ].join(' ')
                }

                // gossip (OpenChannelDialog.qml:72-142)
                RowLayout {
                    Layout.fillWidth: true
                    visible: Config.useGossip
                    spacing: m3.space4

                    M3TextArea {
                        id: nodeUri
                        Layout.fillWidth: true
                        Layout.minimumHeight: nodeUriFontMetrics.lineSpacing * 4 + 2 * m3.space16
                        font.family: FixedFont
                        wrapMode: Text.Wrap
                        placeholderText: qsTranslate('OpenChannelDialog', 'Paste or scan node uri/pubkey')
                        inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                        onTextChanged: {
                            if (nodeUri.textArea.activeFocus)
                                channelopener.connectStr = text
                        }
                        Connections {
                            target: nodeUri.textArea
                            function onActiveFocusChanged() {
                                if (!nodeUri.textArea.activeFocus)
                                    channelopener.connectStr = nodeUri.text
                            }
                        }
                    }
                    ColumnLayout {
                        Layout.alignment: Qt.AlignTop
                        spacing: 0
                        M3IconButton {
                            tooltip: qsTr('Paste')
                            icon.source: Qt.resolvedUrl('../../icons/m3/content_paste.png')
                            onClicked: {
                                var cliptext = AppController.clipboardToText()
                                if (!cliptext)
                                    return
                                if (channelopener.validateConnectString(cliptext)) {
                                    channelopener.connectStr = cliptext
                                    nodeUri.text = channelopener.connectStr
                                } else {
                                    var dialog = app.messageDialog.createObject(app, {
                                        text: qsTranslate('OpenChannelDialog', 'Invalid node-id or connect string')
                                    })
                                    dialog.open()
                                }
                            }
                        }
                        M3IconButton {
                            tooltip: qsTr('Scan QR code')
                            icon.source: Qt.resolvedUrl('../../icons/m3/qr_code_scanner.png')
                            onClicked: {
                                var dialog = app.scanDialog.createObject(app, {
                                    hint: qsTranslate('OpenChannelDialog', 'Scan a node-id or a connect string')
                                })
                                dialog.onFoundText.connect(function(data) {
                                    if (channelopener.validateConnectString(data)) {
                                        channelopener.connectStr = data
                                        nodeUri.text = channelopener.connectStr
                                    } else {
                                        var errdialog = app.messageDialog.createObject(app, {
                                            text: qsTranslate('OpenChannelDialog', 'Invalid node-id or connect string')
                                        })
                                        errdialog.open()
                                    }
                                    dialog.close()
                                })
                                dialog.open()
                            }
                        }
                    }
                }

                // trampoline (OpenChannelDialog.qml:144-161)
                M3ListGroup {
                    Layout.fillWidth: true
                    visible: !Config.useGossip

                    M3SelectRow {
                        headline: qsTr('Trampoline node')
                        model: channelopener.trampolineNodeNames
                        currentValue: root._trampolineNode
                        onSelected: (value) => {
                            root._trampolineNode = value
                            channelopener.connectStr = value
                        }
                    }
                }

                // amount (OpenChannelDialog.qml:165-227)
                M3AmountField {
                    id: amountBtc
                    Layout.fillWidth: true
                    readOnly: is_max.checked
                    onTextAsSatsChanged: {
                        if (!is_max.checked)
                            channelopener.amount = amountBtc.textAsSats
                    }

                    Connections {
                        target: channelopener.amount
                        function onSatsIntChanged() {
                            if (is_max.checked)  // amount updated by max amount estimate
                                amountBtc.text = Config.formatSatsForEditing(channelopener.amount.satsInt)
                        }
                    }

                    trailing: [
                        Switch {
                            id: is_max
                            text: qsTranslate('OpenChannelDialog', 'Max')
                            // the classic reacts to user changes only (activeFocus); onToggled is that
                            onToggled: {
                                channelopener.amount.isMax = checked
                                if (checked) {
                                    channelopener.updateMaxAmount()
                                }
                            }
                        }
                    ]
                }

                M3InfoText {
                    id: warning
                    Layout.fillWidth: true
                    iconStyle: M3InfoText.IconStyle.Warn
                    text: channelopener.warning
                    visible: text
                    compact: true
                }
            }
        }

        TxDialogButtonBar {
            Layout.fillWidth: true
            text: qsTranslate('OpenChannelDialog', 'Open Channel...')
            icon.source: Qt.resolvedUrl('../../icons/m3/check.png')
            enabled: channelopener.valid
            onClicked: channelopener.openChannel()
        }
    }

    // preselect a random node (OpenChannelDialog.qml:154-160)
    Component.onCompleted: {
        if (!Config.useGossip && channelopener.trampolineNodeNames.length > 0) {
            var names = channelopener.trampolineNodeNames
            root._trampolineNode = names[Math.floor(Math.random() * names.length)]
            channelopener.connectStr = root._trampolineNode
        }
    }

    Component {
        id: confirmOpenChannelDialog
        ConfirmTxDialog {
            amountLabelText: qsTranslate('OpenChannelDialog', 'Channel capacity')
            sendButtonText: qsTranslate('OpenChannelDialog', 'Open Channel')
            finalizer: channelopener.finalizer
        }
    }

    ChannelOpener {
        id: channelopener
        wallet: Daemon.currentWallet
        onAuthRequired: (method, authMessage) => {
            app.handleAuthRequired(channelopener, method, authMessage)
        }
        onValidationError: (code, message) => {
            if (code == 'invalid_nodeid') {
                var dialog = app.messageDialog.createObject(app, {
                    title: qsTranslate('OpenChannelDialog', 'Error'),
                    iconSource: Qt.resolvedUrl('../../icons/m3/warning.png'),
                    text: message
                })
                dialog.open()
            }
        }
        onConflictingBackup: (message) => {
            var dialog = app.messageDialog.createObject(app, {
                text: message,
                yesno: true
            })
            dialog.open()
            dialog.accepted.connect(function() {
                channelopener.openChannel(true)
            })
        }
        onFinalizerChanged: {
            var dialog = confirmOpenChannelDialog.createObject(app, {
                satoshis: channelopener.amount
            })
            dialog.accepted.connect(function() {
                dialog.finalizer.signAndSend()
            })
            dialog.open()
        }
        onChannelOpening: (peer) => {
            console.log('Channel is opening')
            app.channelOpenProgressDialog.resetDialog()
            app.channelOpenProgressDialog.peer = peer
            app.channelOpenProgressDialog.open()
        }
        onChannelOpenError: (message) => {
            app.channelOpenProgressDialog.state = 'failed'
            app.channelOpenProgressDialog.error = message
        }
        onChannelOpenSuccess: (cid, has_onchain_backup, min_depth, tx_complete) => {
            var message = qsTranslate('OpenChannelDialog', 'Channel established.') + ' '
                    + qsTranslate('OpenChannelDialog', 'This channel will be usable after %1 confirmations').arg(min_depth)
            if (!tx_complete) {
                message = message + '\n\n' + qsTranslate('OpenChannelDialog', 'Please sign and broadcast the funding transaction.')
                channelopener.wallet.historyModel.initModel(true) // local tx doesn't trigger model update
            }
            app.channelOpenProgressDialog.state = 'success'
            app.channelOpenProgressDialog.info = message
            if (!has_onchain_backup) {
                app.channelOpenProgressDialog.channelBackup = channelopener.channelBackup(cid)
            }
            // TODO: handle incomplete TX
            root.close()
        }
    }

    FontMetrics {
        id: nodeUriFontMetrics
        font: nodeUri.font
    }
}
