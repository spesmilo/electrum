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

    property string channelid

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.preferredWidth: parent.width
            Layout.fillHeight: true

            leftMargin: constants.paddingLarge
            rightMargin: constants.paddingLarge
            topMargin: constants.paddingLarge

            contentHeight: rootLayout.height
            clip:true
            interactive: height < contentHeight

            ColumnLayout {
                id: rootLayout
                width: parent.width

                Heading {
                    text: !channeldetails.isBackup ? qsTr('Lightning Channel') : qsTr('Channel Backup')
                }

                GridLayout {
                    Layout.fillWidth: true
                    columns: 2

                    Label {
                        visible: channeldetails.name
                        text: qsTr('Node name')
                        color: Material.accentColor
                    }

                    Label {
                        Layout.fillWidth: true
                        visible: channeldetails.name
                        text: channeldetails.name
                    }

                    Label {
                        text: qsTr('State')
                        color: Material.accentColor
                    }

                    Label {
                        text: channeldetails.state
                        color: channeldetails.state == 'OPEN'
                                ? constants.colorChannelOpen
                                : Material.foreground
                    }

                    Label {
                        Layout.columnSpan: 2
                        Layout.topMargin: constants.paddingSmall
                        text: qsTr('Capacity and ratio')
                        color: Material.accentColor
                    }

                    TextHighlightPane {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        padding: constants.paddingLarge

                        GridLayout {
                            width: parent.width
                            columns: 2
                            rowSpacing: constants.paddingSmall

                            InfoTextArea {
                                Layout.columnSpan: 2
                                Layout.fillWidth: true
                                Layout.bottomMargin: constants.paddingMedium
                                visible: channeldetails.canSend.msatsInt < 0.5 * channeldetails.localCapacity.msatsInt
                                    && channeldetails.localCapacity.msatsInt > 0.2 * channeldetails.capacity.msatsInt
                                iconStyle: InfoTextArea.IconStyle.Warn
                                compact: true
                                text: [qsTr('The amount available for sending is considerably lower than the local balance.'),
                                    qsTr('This can occur when mempool fees are high.')].join(' ')
                            }

                            ChannelBar {
                                Layout.columnSpan: 2
                                Layout.fillWidth: true
                                Layout.topMargin: constants.paddingLarge
                                Layout.bottomMargin: constants.paddingXLarge
                                visible: channeldetails.stateCode != ChannelDetails.Redeemed
                                    && channeldetails.stateCode != ChannelDetails.Closed
                                    && !channeldetails.isBackup
                                capacity: channeldetails.capacity
                                localCapacity: channeldetails.localCapacity
                                remoteCapacity: channeldetails.remoteCapacity
                                canSend: channeldetails.canSend
                                canReceive: channeldetails.canReceive
                                frozenForSending: channeldetails.frozenForSending
                                frozenForReceiving: channeldetails.frozenForReceiving
                            }

                            Label {
                                text: qsTr('Capacity')
                                color: Material.accentColor
                            }

                            FormattedAmount {
                                amount: channeldetails.capacity
                            }

                            Label {
                                text: qsTr('Can send')
                                color: Material.accentColor
                            }

                            RowLayout {
                                visible: channeldetails.isOpen
                                FormattedAmount {
                                    visible: !channeldetails.frozenForSending
                                    amount: channeldetails.canSend
                                    singleLine: false
                                }
                                Label {
                                    visible: channeldetails.frozenForSending
                                    text: qsTr('n/a (frozen)')
                                }
                                Item {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 1
                                }
                                Pane {
                                    background: Rectangle { color: Material.dialogColor }
                                    padding: 0
                                    FlatButton {
                                        Layout.minimumWidth: implicitWidth
                                        text: channeldetails.frozenForSending ? qsTr('Unfreeze') : qsTr('Freeze')
                                        onClicked: channeldetails.freezeForSending()
                                    }
                                }
                            }

                            Label {
                                visible: !channeldetails.isOpen
                                text: qsTr('n/a (channel not open)')
                            }

                            Label {
                                text: qsTr('Can receive')
                                color: Material.accentColor
                            }

                            RowLayout {
                                visible: channeldetails.isOpen
                                FormattedAmount {
                                    visible: !channeldetails.frozenForReceiving
                                    amount: channeldetails.canReceive
                                    singleLine: false
                                }

                                Label {
                                    visible: channeldetails.frozenForReceiving
                                    text: qsTr('n/a (frozen)')
                                }
                                Item {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 1
                                }
                                Pane {
                                    background: Rectangle { color: Material.dialogColor }
                                    padding: 0
                                    FlatButton {
                                        Layout.minimumWidth: implicitWidth
                                        text: channeldetails.frozenForReceiving ? qsTr('Unfreeze') : qsTr('Freeze')
                                        onClicked: channeldetails.freezeForReceiving()
                                    }
                                }
                            }

                            Label {
                                visible: !channeldetails.isOpen
                                text: qsTr('n/a (channel not open)')
                            }
                        }
                    }

                    Heading {
                        Layout.columnSpan: 2
                        text: qsTr('Technical properties')
                    }

                    Label {
                        text: qsTr('Short channel ID')
                        color: Material.accentColor
                    }

                    Label {
                        Layout.fillWidth: true
                        text: channeldetails.shortCid
                    }

                    Label {
                        visible: !channeldetails.isBackup
                        text: qsTr('Initiator')
                        color: Material.accentColor
                    }

                    Label {
                        visible: !channeldetails.isBackup
                        text: channeldetails.initiator
                    }

                    Label {
                        text: qsTr('Channel type')
                        color: Material.accentColor
                    }

                    Label {
                        text: channeldetails.channelType
                    }

                    Label {
                        visible: channeldetails.isBackup
                        text: qsTr('Backup type')
                        color: Material.accentColor
                    }

                    Label {
                        visible: channeldetails.isBackup
                        text: channeldetails.backupType == 'imported'
                                  ? qsTr('imported')
                                  : channeldetails.backupType == 'on-chain'
                                      ? qsTr('on-chain')
                                      : '?'
                    }

                    Label {
                        Layout.columnSpan: 2
                        Layout.topMargin: constants.paddingSmall
                        text: qsTr('Remote node ID')
                        color: Material.accentColor
                    }

                    TextHighlightPane {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true

                        RowLayout {
                            width: parent.width
                            Label {
                                text: channeldetails.pubkey
                                font.pixelSize: constants.fontSizeLarge
                                font.family: FixedFont
                                Layout.fillWidth: true
                                wrapMode: Text.Wrap
                            }
                            ToolButton {
                                icon.source: '../../icons/share.png'
                                icon.color: 'transparent'
                                onClicked: {
                                    var dialog = app.genericShareDialog.createObject(root, {
                                        title: qsTr('Channel node ID'),
                                        text: channeldetails.pubkey
                                    })
                                    dialog.open()
                                }
                            }
                        }
                    }

                    Label {
                        Layout.columnSpan: 2
                        Layout.topMargin: constants.paddingSmall
                        text: qsTr('Funding Outpoint')
                        color: Material.accentColor
                    }

                    TextHighlightPane {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true

                        RowLayout {
                            width: parent.width
                            Label {
                                text: channeldetails.fundingOutpoint.txid + ':' +  channeldetails.fundingOutpoint.index
                                font.pixelSize: constants.fontSizeLarge
                                font.family: FixedFont
                                Layout.fillWidth: true
                                wrapMode: Text.Wrap

                                TapHandler {
                                    onTapped: {
                                        app.stack.push(Qt.resolvedUrl('TxDetails.qml'), {
                                            txid: channeldetails.fundingOutpoint.txid
                                        })
                                    }
                                }
                            }
                            ToolButton {
                                icon.source: '../../icons/share.png'
                                icon.color: 'transparent'
                                onClicked: {
                                    var dialog = app.genericShareDialog.createObject(root, {
                                        title: qsTr('Funding Outpoint'),
                                        text: channeldetails.fundingOutpoint.txid + ':' + channeldetails.fundingOutpoint.index
                                    })
                                    dialog.open()
                                }
                            }
                        }
                    }

                    Label {
                        Layout.columnSpan: 2
                        Layout.topMargin: constants.paddingSmall
                        visible: channeldetails.closingTxid
                        text: qsTr('Closing transaction')
                        color: Material.accentColor
                    }

                    TextHighlightPane {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        visible: channeldetails.closingTxid

                        RowLayout {
                            width: parent.width
                            Label {
                                text: channeldetails.closingTxid
                                font.pixelSize: constants.fontSizeLarge
                                font.family: FixedFont
                                Layout.fillWidth: true
                                wrapMode: Text.Wrap

                                TapHandler {
                                    onTapped: {
                                        app.stack.push(Qt.resolvedUrl('TxDetails.qml'), {
                                            txid: channeldetails.closingTxid
                                        })
                                    }
                                }
                            }
                            ToolButton {
                                icon.source: '../../icons/share.png'
                                icon.color: 'transparent'
                                onClicked: {
                                    var dialog = app.genericShareDialog.createObject(root, {
                                        title: qsTr('Channel close transaction'),
                                        text: channeldetails.closingTxid
                                    })
                                    dialog.open()
                                }
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
                visible: !channeldetails.isBackup
                text: qsTr('Backup')
                icon.source: '../../icons/file.png'
                onClicked: {
                    var dialog = app.genericShareDialog.createObject(root, {
                        title: qsTr('Channel Backup for %1').arg(channeldetails.shortCid),
                        text_qr: channeldetails.channelBackup(),
                        text_help: channeldetails.channelBackupHelpText(),
                        iconSource: Qt.resolvedUrl('../../icons/file.png')
                    })
                    dialog.open()
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Close channel');
                visible: channeldetails.canClose
                icon.source: '../../icons/closebutton.png'
                onClicked: {
                    var dialog = closechannel.createObject(root, { channelid: channelid })
                    dialog.open()
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Delete channel');
                visible: channeldetails.canDelete
                icon.source: '../../icons/delete.png'
                onClicked: {
                    var dialog = app.messageDialog.createObject(root, {
                        title: qsTr('Are you sure?'),
                        text: channeldetails.isBackup ? '' : qsTr('This will purge associated transactions from your wallet history.'),
                        yesno: true
                    })
                    dialog.accepted.connect(function() {
                        channeldetails.deleteChannel()
                        app.stack.pop()
                        Daemon.currentWallet.historyModel.initModel(true) // needed here?
                        Daemon.currentWallet.channelModel.removeChannel(channelid)
                    })
                    dialog.open()
                }
            }
        }

    }

    ChannelDetails {
        id: channeldetails
        wallet: Daemon.currentWallet
        channelid: root.channelid
        onTrampolineFrozenInGossipMode: {
            var dialog = app.messageDialog.createObject(root, {
                title: qsTr('Cannot unfreeze channel'),
                text: [qsTr('Non-Trampoline channels cannot be used for sending while in trampoline mode.'),
                        qsTr('Disable trampoline mode to enable sending from this channel.')].join(' ')
            })
            dialog.open()
        }
    }

    Component {
        id: closechannel
        CloseChannelDialog {}
    }
}
