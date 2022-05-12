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

        TextArea {
            id: node
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
            spacing: 0
            ToolButton {
                icon.source: '../../icons/paste.png'
                icon.height: constants.iconSizeMedium
                icon.width: constants.iconSizeMedium
                onClicked: {
                    channelopener.nodeid = AppController.clipboardToText()
                    node.text = channelopener.nodeid
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
                        channelopener.nodeid = page.scanData
                        node.text = channelopener.nodeid
                    })
                }
            }
        }

        Label {
            text: qsTr('Amount')
        }

        BtcField {
            id: amount
            fiatfield: amountFiat
            Layout.preferredWidth: parent.width /2
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
                    if (checked) {
                        channelopener.amount = MAX
                    }
                }
            }
        }

        Item { width: 1; height: 1; visible: Daemon.fx.enabled }

        FiatField {
            id: amountFiat
            btcfield: amount
            visible: Daemon.fx.enabled
            Layout.preferredWidth: parent.width /2
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
            var dialog = app.messageDialog.createObject(root, { 'text': message })
            dialog.open()
            dialog.yesClicked.connect(function() {
                channelopener.open_channel(true)
            })
        }
    }

}
