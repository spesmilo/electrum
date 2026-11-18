import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// Lightning channel details of the Material 3 GUI (route app.routes.channelDetails, opened from the channel list of
// the Channels tab; replaces the classic ChannelDetails).
// repeats: components/ChannelDetails.qml:10-482: the page contract (the only property `channelid`, not
// required, as in the classic page), the
// ChannelDetails object and its trampolineFrozenInGossipMode message; node name, state (highlighted when OPEN);
// capacity and ratio: the capacity bar (not for redeemed / closed channels and backups), capacity, local balance,
// can send and can receive (n/a while the channel is not open, n/a (frozen) while frozen) with Freeze / Unfreeze
// (freezeForSending() / freezeForReceiving()); the technical properties and their conditions (short channel ID,
// local and remote SCID alias, initiator, channel type, current feerate, backup type, remote node ID, funding
// outpoint, closing transaction) with sharing; the funding and the closing transaction open the transaction details
// (the classic pushes TxDetails.qml, here the route app.routes.txDetails with the same `txid`); Backup (the channel
// backup in app.genericShareDialog with its help text), Close channel (CloseChannelDialog with `channelid`) and
// Delete channel ("Are you sure?", then deleteChannel(), back to the list, the history and the channel list
// updated) with their conditions.
// Layout: the details are M3DetailRow rows in groups; Backup and Close channel are buttons below
// the content; Delete channel, rare and destructive, is in the overflow menu of the top app bar (`m3Actions`).
// The close dialog is not destroyed when it closes, as in the classic (ChannelDetails.qml:478-481): it lives until
// the page goes, so the result of a close still running when the dialog was closed with X or back (its
// channelCloseSuccess message) still reaches the user.
// Strings keep the translation context of the classic file (qsTranslate('ChannelDetails', ...)).
M3Page {
    id: root

    property string channelid

    title: !channeldetails.isBackup
        ? qsTranslate('ChannelDetails', 'Lightning Channel')
        : qsTranslate('ChannelDetails', 'Channel Backup')

    // ChannelDetails.qml:439-459 (Delete channel): the overflow menu, shown when the channel can be deleted
    property list<Item> m3Actions: [
        M3IconButton {
            visible: channeldetails.canDelete
            tooltip: qsTr('More options')
            icon.source: Qt.resolvedUrl('../../icons/m3/more_vert.png')
            onClicked: overflowMenu.open()
        }
    ]

    // ChannelDetails.qml:416-424
    function showBackup() {
        var dialog = app.genericShareDialog.createObject(root, {
            title: qsTranslate('ChannelDetails', 'Channel Backup for %1').arg(channeldetails.shortCid),
            text_qr: channeldetails.channelBackup(),
            text_help: channeldetails.channelBackupHelpText(),
            iconSource: Qt.resolvedUrl('../../icons/m3/backup.png')
        })
        dialog.open()
    }

    // ChannelDetails.qml:433-436
    function closeChannel() {
        var dialog = closechannel.createObject(root, { channelid: channelid })
        dialog.open()
    }

    // ChannelDetails.qml:445-458
    function deleteChannel() {
        var dialog = app.messageDialog.createObject(root, {
            title: qsTranslate('ChannelDetails', 'Are you sure?'),
            text: channeldetails.isBackup ? '' : qsTranslate('ChannelDetails', 'This will purge associated transactions from your wallet history.'),
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

                M3ListGroup {
                    Layout.fillWidth: true

                    M3DetailRow {
                        visible: channeldetails.name
                        label: qsTranslate('ChannelDetails', 'Node name')
                        text: channeldetails.name
                    }

                    M3DetailRow {
                        label: qsTranslate('ChannelDetails', 'State')
                        text: channeldetails.state
                        valueColor: channeldetails.state == 'OPEN' ? m3.success : m3.surfaceOn
                    }
                }

                // --- capacity and ratio (ChannelDetails.qml:70-193) ---
                M3SectionHeader {
                    Layout.fillWidth: true
                    Layout.bottomMargin: -m3.space8
                    leftPadding: 0
                    text: qsTranslate('ChannelDetails', 'Capacity and ratio')
                }

                M3ListGroup {
                    Layout.fillWidth: true

                    Item {
                        Layout.fillWidth: true
                        visible: channeldetails.stateCode != ChannelDetails.Redeemed
                            && channeldetails.stateCode != ChannelDetails.Closed
                            && !channeldetails.isBackup
                        implicitHeight: bar.implicitHeight + 2 * m3.space16

                        M3ChannelBar {
                            id: bar
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.leftMargin: m3.space16
                            anchors.rightMargin: m3.space16
                            anchors.verticalCenter: parent.verticalCenter
                            capacity: channeldetails.capacity
                            localCapacity: channeldetails.localCapacity
                            remoteCapacity: channeldetails.remoteCapacity
                            canSend: channeldetails.canSend
                            canReceive: channeldetails.canReceive
                            frozenForSending: channeldetails.frozenForSending
                            frozenForReceiving: channeldetails.frozenForReceiving
                        }
                    }

                    ChannelAmountRow {
                        label: qsTranslate('ChannelDetails', 'Capacity')
                        amount: channeldetails.capacity
                    }

                    ChannelAmountRow {
                        label: qsTranslate('ChannelDetails', 'Local balance')
                        amount: channeldetails.localCapacity
                        showAmount: channeldetails.isOpen
                        naText: qsTranslate('ChannelDetails', 'n/a (channel not open)')
                    }

                    ChannelAmountRow {
                        label: qsTranslate('ChannelDetails', 'Can send')
                        amount: channeldetails.canSend
                        showAmount: channeldetails.isOpen && !channeldetails.frozenForSending
                        naText: !channeldetails.isOpen
                            ? qsTranslate('ChannelDetails', 'n/a (channel not open)')
                            : qsTranslate('ChannelDetails', 'n/a (frozen)')
                        showFreeze: channeldetails.isOpen
                        frozen: channeldetails.frozenForSending
                        onFreezeClicked: channeldetails.freezeForSending()
                    }

                    ChannelAmountRow {
                        label: qsTranslate('ChannelDetails', 'Can receive')
                        amount: channeldetails.canReceive
                        showAmount: channeldetails.isOpen && !channeldetails.frozenForReceiving
                        naText: !channeldetails.isOpen
                            ? qsTranslate('ChannelDetails', 'n/a (channel not open)')
                            : qsTranslate('ChannelDetails', 'n/a (frozen)')
                        showFreeze: channeldetails.isOpen
                        frozen: channeldetails.frozenForReceiving
                        onFreezeClicked: channeldetails.freezeForReceiving()
                    }
                }

                // --- technical properties (ChannelDetails.qml:195-401) ---
                M3SectionHeader {
                    Layout.fillWidth: true
                    Layout.bottomMargin: -m3.space8
                    leftPadding: 0
                    text: qsTranslate('ChannelDetails', 'Technical properties')
                }

                M3ListGroup {
                    Layout.fillWidth: true

                    M3DetailRow {
                        label: qsTranslate('ChannelDetails', 'Short channel ID')
                        text: channeldetails.shortCid
                    }

                    M3DetailRow {
                        visible: channeldetails.localScidAlias
                        label: qsTranslate('ChannelDetails', 'Local SCID alias')
                        text: channeldetails.localScidAlias
                    }

                    M3DetailRow {
                        visible: channeldetails.remoteScidAlias
                        label: qsTranslate('ChannelDetails', 'Remote SCID alias')
                        text: channeldetails.remoteScidAlias
                    }

                    M3DetailRow {
                        visible: !channeldetails.isBackup
                        label: qsTranslate('ChannelDetails', 'Initiator')
                        text: channeldetails.initiator
                    }

                    M3DetailRow {
                        label: qsTranslate('ChannelDetails', 'Channel type')
                        text: channeldetails.channelType
                    }

                    M3DetailRow {
                        visible: channeldetails.currentFeerate
                        label: qsTranslate('ChannelDetails', 'Current feerate')
                        text: channeldetails.currentFeerate
                    }

                    M3DetailRow {
                        visible: channeldetails.isBackup
                        label: qsTranslate('ChannelDetails', 'Backup type')
                        text: channeldetails.backupType == 'imported'
                                  ? qsTranslate('ChannelDetails', 'imported')
                                  : channeldetails.backupType == 'on-chain'
                                      ? qsTranslate('ChannelDetails', 'on-chain')
                                      : '?'
                    }

                    M3DetailRow {
                        label: qsTranslate('ChannelDetails', 'Remote node ID')
                        text: channeldetails.pubkey
                        monospace: true
                        shareable: true
                        shareTitle: qsTranslate('ChannelDetails', 'Channel node ID')
                    }

                    M3DetailRow {
                        id: fundingRow
                        label: qsTranslate('ChannelDetails', 'Funding Outpoint')
                        text: channeldetails.fundingOutpoint.txid + ':' +  channeldetails.fundingOutpoint.index
                        monospace: true
                        shareable: true
                        shareTitle: qsTranslate('ChannelDetails', 'Funding Outpoint')
                        actions: [
                            M3IconButton {
                                tooltip: qsTranslate('TxDetails', 'On-chain Transaction')
                                icon.source: Qt.resolvedUrl('../../icons/m3/open_in_new.png')
                                onClicked: app.pushPage(app.routes.txDetails, {
                                    txid: channeldetails.fundingOutpoint.txid
                                })
                            }
                        ]
                    }

                    M3DetailRow {
                        visible: channeldetails.closingTxid
                        label: qsTranslate('ChannelDetails', 'Closing transaction')
                        text: channeldetails.closingTxid
                        monospace: true
                        shareable: true
                        shareTitle: qsTranslate('ChannelDetails', 'Channel close transaction')
                        actions: [
                            M3IconButton {
                                tooltip: qsTranslate('TxDetails', 'On-chain Transaction')
                                icon.source: Qt.resolvedUrl('../../icons/m3/open_in_new.png')
                                onClicked: app.pushPage(app.routes.txDetails, {
                                    txid: channeldetails.closingTxid
                                })
                            }
                        ]
                    }
                }
            }
        }

        // --- main actions (ChannelDetails.qml:407-437): below the content ---
        Rectangle {
            Layout.fillWidth: true
            // the conditions of the buttons, not their `visible` (that of a child of a hidden item is false)
            visible: !channeldetails.isBackup || channeldetails.canClose
            implicitHeight: actions.implicitHeight + 2 * m3.space16
            color: m3.surface

            GridLayout {
                id: actions
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
                columns: 2 * Math.max(backupButton.implicitWidth, closeButton.implicitWidth) + columnSpacing <= width ? 2 : 1
                rowSpacing: m3.space8
                columnSpacing: m3.space8

                M3Button {
                    id: backupButton
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    Layout.columnSpan: channeldetails.canClose ? 1 : actions.columns
                    variant: 'tonal'
                    size: 56
                    visible: !channeldetails.isBackup
                    text: qsTranslate('ChannelDetails', 'Backup')
                    icon.source: Qt.resolvedUrl('../../icons/m3/backup.png')
                    onClicked: root.showBackup()
                }

                M3Button {
                    id: closeButton
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    Layout.columnSpan: !channeldetails.isBackup ? 1 : actions.columns
                    variant: 'outlined'
                    size: 56
                    visible: channeldetails.canClose
                    text: qsTranslate('ChannelDetails', 'Close channel')
                    icon.source: Qt.resolvedUrl('../../icons/m3/link_off.png')
                    onClicked: root.closeChannel()
                }
            }
        }
    }

    // --- rare actions: the overflow menu of the top app bar ---
    M3Menu {
        id: overflowMenu
        x: app.width - overflowMenu.width - m3.space8
        y: app.header ? app.header.height - m3.space8 : 0

        MenuItem {
            text: qsTranslate('ChannelDetails', 'Delete channel')
            icon.source: Qt.resolvedUrl('../../icons/m3/delete.png')
            visible: channeldetails.canDelete
            height: visible ? implicitHeight : 0
            onTriggered: root.deleteChannel()
        }
    }

    // a label above an amount (or the n/a text), with the optional Freeze / Unfreeze button on the right
    // (ChannelDetails.qml:104-191)
    component ChannelAmountRow: Item {
        id: amountRow
        property string label
        property var amount
        property bool showAmount: true
        property string naText
        property bool showFreeze: false
        property bool frozen: false
        readonly property bool wide: amountRow.width >= 560
        signal freezeClicked()

        Layout.fillWidth: true
        implicitHeight: Math.max(56, amountLayout.implicitHeight + 2 * m3.space8)

        RowLayout {
            id: amountLayout
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.leftMargin: m3.space16
            anchors.rightMargin: m3.space8
            anchors.verticalCenter: parent.verticalCenter
            spacing: m3.space8

            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2

                M3Text {
                    Layout.fillWidth: true
                    role: 'bodySmall'
                    color: m3.surfaceVariantOn
                    wrapMode: Text.Wrap
                    text: amountRow.label
                }
                Loader {
                    Layout.fillWidth: true
                    active: amountRow.showAmount && amountRow.amount !== undefined && amountRow.amount !== null
                    visible: active
                    sourceComponent: M3Amount {
                        amount: amountRow.amount
                        fiatBelow: !amountRow.wide
                        fiatRole: 'bodyMedium'
                    }
                }
                M3Text {
                    Layout.fillWidth: true
                    visible: !amountRow.showAmount
                    role: 'bodyLarge'
                    wrapMode: Text.Wrap
                    text: amountRow.naText
                }
            }

            M3Button {
                Layout.alignment: Qt.AlignVCenter
                visible: amountRow.showFreeze
                variant: 'text'
                icon.source: Qt.resolvedUrl('../../icons/m3/ac_unit.png')
                text: amountRow.frozen
                    ? qsTranslate('ChannelDetails', 'Unfreeze')
                    : qsTranslate('ChannelDetails', 'Freeze')
                onClicked: amountRow.freezeClicked()
            }
        }
    }

    ChannelDetails {
        id: channeldetails
        wallet: Daemon.currentWallet
        channelid: root.channelid
        onTrampolineFrozenInGossipMode: {
            var dialog = app.messageDialog.createObject(root, {
                title: qsTranslate('ChannelDetails', 'Cannot unfreeze channel'),
                text: [qsTranslate('ChannelDetails', 'Non-Trampoline channels cannot be used for sending while in trampoline mode.'),
                        qsTranslate('ChannelDetails', 'Disable trampoline mode to enable sending from this channel.')].join(' ')
            })
            dialog.open()
        }
    }

    // ChannelDetails.qml:478-481: not destroyed on close (see the header)
    Component {
        id: closechannel
        CloseChannelDialog {}
    }
}
