import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Pane {
    id: root

    property string title: qsTr("Open Lightning Channel")

    GridLayout {
        id: form
        width: parent.width
        rowSpacing: constants.paddingSmall
        columnSpacing: constants.paddingSmall
        columns: 4

        Label {
            text: qsTr('Node')
        }

        // gossip
        TextArea {
            id: node
            visible: Config.useGossip
            Layout.columnSpan: 2
            Layout.fillWidth: true
            font.family: FixedFont
            wrapMode: Text.Wrap
            placeholderText: qsTr('Paste or scan node uri/pubkey')
            onActiveFocusChanged: {
                if (!activeFocus)
                    channelopener.nodeid = text
            }
        }

        RowLayout {
            visible: Config.useGossip
            spacing: 0
            ToolButton {
                icon.source: '../../icons/paste.png'
                icon.height: constants.iconSizeMedium
                icon.width: constants.iconSizeMedium
                onClicked: {
                    if (channelopener.validate_nodeid(AppController.clipboardToText())) {
                        channelopener.nodeid = AppController.clipboardToText()
                        node.text = channelopener.nodeid
                    }
                }
            }
            ToolButton {
                icon.source: '../../icons/qrcode.png'
                icon.height: constants.iconSizeMedium
                icon.width: constants.iconSizeMedium
                scale: 1.2
                onClicked: {
                    var page = app.stack.push(Qt.resolvedUrl('Scan.qml'))
                    page.onFound.connect(function() {
                        if (channelopener.validate_nodeid(page.scanData)) {
                            channelopener.nodeid = page.scanData
                            node.text = channelopener.nodeid
                        }
                    })
                }
            }
        }

        // trampoline
        ComboBox {
            visible: !Config.useGossip
            Layout.columnSpan: 3
            Layout.fillWidth: true
            model: channelopener.trampolineNodeNames
            onCurrentValueChanged: {
                if (activeFocus)
                    channelopener.nodeid = currentValue
            }
            // preselect a random node
            Component.onCompleted: {
                if (!Config.useGossip) {
                    currentIndex = Math.floor(Math.random() * channelopener.trampolineNodeNames.length)
                    channelopener.nodeid = currentValue
                }
            }
        }

        Label {
            text: qsTr('Amount')
        }

        BtcField {
            id: amount
            fiatfield: amountFiat
            Layout.preferredWidth: parent.width /3
            onTextChanged: channelopener.amount = Config.unitsToSats(amount.text)
            enabled: !is_max.checked
        }

        RowLayout {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            Label {
                text: Config.baseUnit
                color: Material.accentColor
            }
            Switch {
                id: is_max
                text: qsTr('Max')
                onCheckedChanged: {
                    channelopener.amount = checked ? MAX : Config.unitsToSats(amount.text)
                }
            }
        }

        Item { width: 1; height: 1; visible: Daemon.fx.enabled }

        FiatField {
            id: amountFiat
            btcfield: amount
            visible: Daemon.fx.enabled
            Layout.preferredWidth: parent.width /3
            enabled: !is_max.checked
        }

        Label {
            visible: Daemon.fx.enabled
            text: Daemon.fx.fiatCurrency
            color: Material.accentColor
            Layout.fillWidth: true
        }

        Item { visible: Daemon.fx.enabled ; height: 1; width: 1 }

        RowLayout {
            Layout.columnSpan: 4
            Layout.alignment: Qt.AlignHCenter

            Button {
                text: qsTr('Open Channel')
                enabled: channelopener.valid
                onClicked: channelopener.open_channel()
            }
        }
    }

    Component {
        id: confirmOpenChannelDialog
        ConfirmTxDialog {
            title: qsTr('Confirm Open Channel')
            amountLabelText: qsTr('Channel capacity')
            sendButtonText: qsTr('Open Channel')
            finalizer: channelopener.finalizer
        }
    }


    ChannelOpener {
        id: channelopener
        wallet: Daemon.currentWallet
        onValidationError: {
            if (code == 'invalid_nodeid') {
                var dialog = app.messageDialog.createObject(root, { 'text': message })
                dialog.open()
            }
        }
        onConflictingBackup: {
            var dialog = app.messageDialog.createObject(root, { 'text': message, 'yesno': true })
            dialog.open()
            dialog.yesClicked.connect(function() {
                channelopener.open_channel(true)
            })
        }
        onFinalizerChanged: {
            var dialog = confirmOpenChannelDialog.createObject(root, {
                'satoshis': channelopener.amount
            })
            dialog.open()
        }
        onChannelOpenError: {
            var dialog = app.messageDialog.createObject(root, { 'text': message })
            dialog.open()
        }
        onChannelOpenSuccess: {
            var message = 'success!'
            if (!has_backup)
                message = message + ' (but no backup. TODO: show QR)'
            var dialog = app.messageDialog.createObject(root, { 'text': message })
            dialog.open()
            channelopener.wallet.channelModel.new_channel(cid)
            app.stack.pop()
        }
    }

}
