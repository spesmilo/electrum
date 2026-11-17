import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// Channels tab of the Material 3 GUI (M2-MAP F-9: the Lightning channels right in the tab, replaces the classic
// Channels page that the tab used to open full screen).
// repeats: components/Channels.qml:10-168 @ e6df7e1c8: the summary (number of open channels, what can be sent /
// received), the channel list over Daemon.currentWallet.channelModel with the "Channel backups" section and the
// empty-list text, a tap opens the channel details (route app.routes.channelDetails with `channelid`, as the
// classic push of ChannelDetails.qml with { channelid: model.cid }), Swap (app.startSwap()) and Open Channel with
// their conditions; Open Channel with no channel yet first shows the Lightning warning and asks whether to create
// the first channel (Channels.qml:137-153, M2-MAP F-12: only on this path, BalanceDetailsPage opens the dialog
// directly), then opens app.openChannelDialog (the one factory of both paths).
// The model and the amounts are bound only while the wallet has Lightning (the channel model of a wallet without
// lnworker logs "lnworker should be defined", qechannellistmodel.py:128-133): a wallet without Lightning gets a
// note (as the classic wallet menu hides Channels for it), and once Lightning is enabled in Wallet details
// (isLightningChanged) the list appears without a restart.
// Layout (M2-MAP F-3): summary, then the two actions as tonal buttons, then the list (one scrolling view; rows in
// a column of at most m3.maxContentWidth, as M3HistoryList).
// Strings carried over keep the translation context of the classic file (qsTranslate('Channels', ...)).
Item {
    id: root

    readonly property bool _lightning: Daemon.currentWallet !== null && Daemon.currentWallet.isLightning
    readonly property bool _canEnable: Daemon.currentWallet !== null && !_lightning && Daemon.currentWallet.canHaveLightning

    // Channels.qml:137-153
    function openChannel() {
        if (Daemon.currentWallet.channelModel.count == 0) {
            var txt = Daemon.currentWallet.channelModel.lightningWarningMessage() + '\n\n' +
                qsTranslate('Channels', 'Do you want to create your first channel?')
            var confirmdialog = app.messageDialog.createObject(root, {
                text: txt,
                yesno: true
            })
            confirmdialog.accepted.connect(function () {
                var dialog = app.openChannelDialog.createObject(root)
                dialog.open()
            })
            confirmdialog.open()
        } else {
            var dialog = app.openChannelDialog.createObject(root)
            dialog.open()
        }
    }

    // ------------------------------------------------ no Lightning
    Flickable {
        anchors.fill: parent
        visible: !root._lightning
        contentHeight: Math.max(height, stub.implicitHeight + 2 * m3.space16)
        clip: true
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: stub
            y: Math.max(m3.space16, (parent.height - implicitHeight) / 3)
            width: Math.min(parent.width, m3.maxContentWidth) - 2 * m3.screenMargin(parent.width)
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: m3.space16

            M3Icon {
                Layout.alignment: Qt.AlignHCenter
                source: Qt.resolvedUrl('../../icons/m3/hub.png')
                size: 48
                color: m3.surfaceVariantOn
            }
            M3Text {
                Layout.fillWidth: true
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
                role: 'titleMedium'
                text: qsTr('This wallet has no Lightning')
            }
            // the wallet can have Lightning: Wallet details has "Enable Lightning"
            M3Text {
                Layout.fillWidth: true
                visible: root._canEnable
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
                role: 'bodyMedium'
                color: m3.surfaceVariantOn
                text: qsTr('Lightning can be enabled in Wallet details.')
            }
            M3Button {
                Layout.alignment: Qt.AlignHCenter
                visible: root._canEnable
                variant: 'tonal'
                text: qsTranslate('WalletMainView', 'Wallet details')
                onClicked: app.pushPageOnRoot(app.routes.walletDetails)
            }
        }
    }

    // ------------------------------------------------ Lightning
    ListView {
        id: listview
        anchors.fill: parent
        visible: root._lightning
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        bottomMargin: m3.space16
        model: root._lightning ? Daemon.currentWallet.channelModel : null

        readonly property int _margin: m3.screenMargin(width)
        readonly property int _columnWidth: Math.min(width, m3.maxContentWidth) - 2 * _margin
        readonly property bool _empty: !root._lightning || count == 0

        header: Item {
            width: ListView.view.width
            height: summary.implicitHeight + m3.space16

            ColumnLayout {
                id: summary
                y: m3.space16
                width: listview._columnWidth
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: m3.space16

                M3Text {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    role: 'titleMedium'
                    text: root._lightning
                        ? qsTranslate('Channels', 'You have %1 open channels').arg(Daemon.currentWallet.channelModel.numOpenChannels)
                        : ''
                }

                M3ListGroup {
                    Layout.fillWidth: true

                    ChannelsAmountRow {
                        title: qsTranslate('Channels', 'You can send')
                        amount: root._lightning ? Daemon.currentWallet.lightningCanSend : null
                    }
                    ChannelsAmountRow {
                        title: qsTranslate('Channels', 'You can receive')
                        amount: root._lightning ? Daemon.currentWallet.lightningCanReceive : null
                    }
                }

                // side by side when both labels fit, else one above the other
                GridLayout {
                    id: actions
                    Layout.fillWidth: true
                    columns: 2 * Math.max(swapButton.implicitWidth, channelButton.implicitWidth) + columnSpacing <= width ? 2 : 1
                    rowSpacing: m3.space8
                    columnSpacing: m3.space8

                    M3Button {
                        id: swapButton
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        variant: 'tonal'
                        text: qsTranslate('Channels', 'Swap')
                        enabled: root._lightning && (Daemon.currentWallet.lightningCanSend.satsInt > 0 ||
                            (Daemon.currentWallet.lightningCanReceive.satsInt > 0 && Daemon.currentWallet.confirmedBalance.satsInt > 0))
                        icon.source: Qt.resolvedUrl('../../icons/m3/swap_horiz.png')
                        onClicked: app.startSwap()
                    }

                    M3Button {
                        id: channelButton
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        variant: 'tonal'
                        enabled: root._lightning && Daemon.currentWallet.canHaveLightning && Daemon.currentWallet.confirmedBalance.satsInt > 0
                        text: qsTranslate('Channels', 'Open Channel')
                        icon.source: Qt.resolvedUrl('../../icons/m3/bolt.png')
                        onClicked: root.openChannel()
                    }
                }

                M3SectionHeader {
                    Layout.fillWidth: true
                    Layout.bottomMargin: -m3.space16
                    visible: !listview._empty
                    text: qsTranslate('Channels', 'Lightning Channels')
                }

                // the empty list (Channels.qml:105-114)
                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: m3.space32
                    visible: listview._empty
                    spacing: m3.space16

                    M3Icon {
                        Layout.alignment: Qt.AlignHCenter
                        source: Qt.resolvedUrl('../../icons/m3/hub.png')
                        size: 48
                        color: m3.surfaceVariantOn
                    }
                    M3Text {
                        Layout.fillWidth: true
                        horizontalAlignment: Text.AlignHCenter
                        wrapMode: Text.Wrap
                        role: 'bodyLarge'
                        color: m3.surfaceVariantOn
                        text: qsTranslate('Channels', 'No Lightning channels yet in this wallet')
                    }
                }
            }
        }

        // Channels.qml:79-91: a label above the backups only
        section.property: 'is_backup'
        section.criteria: ViewSection.FullString
        section.delegate: Item {
            required property string section
            width: ListView.view.width
            height: section == 'true' ? backupsHeader.implicitHeight : 0
            M3SectionHeader {
                id: backupsHeader
                visible: section == 'true'
                width: listview._columnWidth
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTranslate('Channels', 'Channel backups')
            }
        }

        delegate: Item {
            width: ListView.view.width
            height: row.height
            M3ChannelDelegate {
                id: row
                width: listview._columnWidth + 2 * m3.space16
                anchors.horizontalCenter: parent.horizontalCenter
                onClicked: {
                    app.pushPage(app.routes.channelDetails, { 'channelid': model.cid })
                }
            }
        }

        ScrollIndicator.vertical: ScrollIndicator { }
    }

    // a title and an amount (with fiat, as the classic FormattedAmount) in one row
    component ChannelsAmountRow: RowLayout {
        id: amountRow
        property string title
        property var amount

        Layout.fillWidth: true
        Layout.leftMargin: m3.space16
        Layout.rightMargin: m3.space16
        Layout.topMargin: m3.space12
        Layout.bottomMargin: m3.space12
        spacing: m3.space16

        M3Text {
            Layout.fillWidth: true
            role: 'bodyLarge'
            wrapMode: Text.Wrap
            text: amountRow.title
        }
        Loader {
            Layout.alignment: Qt.AlignRight
            active: amountRow.amount !== null && amountRow.amount !== undefined
            sourceComponent: M3Amount {
                amount: amountRow.amount
                role: 'titleMedium'
                unitRole: 'bodyMedium'
                fiatRole: 'bodySmall'
            }
        }
    }
}
