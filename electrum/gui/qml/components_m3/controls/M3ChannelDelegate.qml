import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import org.electrum 1.0

// One Lightning channel in the channel list of the Material 3 Channels tab, a delegate of a view over
// Daemon.currentWallet.channelModel: reads the roles of qechannellistmodel.py through the context property
// `model`, as the classic delegate does.
// repeats: components/controls/ChannelDelegate.qml:8-133 (closed = state Closed or Redeemed and dimmed;
// the icon by kind: imported backup, on-chain backup, trampoline, normal; node alias, else the node id in the
// fixed font (2 lines for an alias, 1 for an id); the state, highlighted when OPEN; the short channel id; the
// capacity with the base unit; the capacity bar for channels that are neither closed nor backups).
// Look: a 40 dp avatar with a Material 3 glyph instead of the colored classic icons: normal and
// trampoline channels `bolt` on tertiaryContainer (the Lightning role), an on-chain backup `link_off` and an
// imported backup `cloud_off` on surfaceContainerHighest; a trampoline channel says "Trampoline" after the short
// channel id (no kangaroo glyph in Material Symbols). The OPEN state is in m3.success.
ItemDelegate {
    id: root

    width: ListView.view ? ListView.view.width : implicitWidth
    implicitHeight: layout.implicitHeight + 2 * m3.space12

    leftPadding: m3.space16
    rightPadding: m3.space16
    topPadding: m3.space12
    bottomPadding: m3.space12

    readonly property bool _closed: model.state_code == ChannelDetails.Closed
                            || model.state_code == ChannelDetails.Redeemed
    readonly property color _mainColor: _closed ? m3.surfaceVariantOn : m3.surfaceOn

    background: Rectangle {
        color: root.down
            ? Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.statePressed)
            : root.hovered || root.visualFocus
                ? Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.stateHover)
                : 'transparent'
    }

    contentItem: RowLayout {
        id: layout
        spacing: m3.space16

        Rectangle {
            Layout.alignment: Qt.AlignTop
            implicitWidth: 40
            implicitHeight: 40
            radius: 20
            opacity: root._closed ? 0.5 : 1.0
            color: model.is_backup ? m3.surfaceContainerHighest : m3.tertiaryContainer
            M3Icon {
                anchors.centerIn: parent
                size: 24
                source: Qt.resolvedUrl(model.is_backup
                        ? model.is_imported
                            ? '../../../icons/m3/cloud_off.png'
                            : '../../../icons/m3/link_off.png'
                        : '../../../icons/m3/bolt.png')
                color: model.is_backup ? m3.surfaceVariantOn : m3.tertiaryContainerOn
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: m3.space4

            RowLayout {
                Layout.fillWidth: true
                spacing: m3.space8

                M3Text {
                    Layout.fillWidth: true
                    role: model.node_alias ? 'bodyLarge' : 'bodyMedium'
                    text: model.node_alias ? model.node_alias : model.node_id
                    font.family: model.node_alias ? fontRef.font.family : FixedFont
                    elide: Text.ElideRight
                    wrapMode: model.node_alias ? Text.Wrap : Text.NoWrap
                    maximumLineCount: model.node_alias ? 2 : 1
                    color: root._mainColor
                }

                M3Text {
                    Layout.alignment: Qt.AlignTop
                    role: 'labelLarge'
                    text: model.state
                    color: root._closed
                        ? m3.surfaceVariantOn
                        : model.state == 'OPEN'
                            ? m3.success
                            : m3.surfaceOn
                }
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: m3.space8

                M3Text {
                    Layout.fillWidth: true
                    role: 'bodyMedium'
                    color: m3.surfaceVariantOn
                    elide: Text.ElideRight
                    text: model.is_trampoline && !model.is_backup
                        ? model.short_cid + ' \u00B7 ' + qsTr('Trampoline')
                        : model.short_cid
                }

                M3Text {
                    role: 'bodyMedium'
                    font.family: FixedFont
                    text: Config.formatSats(model.capacity)
                    color: root._mainColor
                }

                M3Text {
                    role: 'bodyMedium'
                    text: Config.baseUnit
                    color: m3.surfaceVariantOn
                }
            }

            M3ChannelBar {
                Layout.fillWidth: true
                Layout.topMargin: m3.space4
                visible: !root._closed && !model.is_backup
                capacity: model.capacity
                localCapacity: model.local_capacity
                remoteCapacity: model.remote_capacity
                canSend: model.can_send
                canReceive: model.can_receive
                frozenForSending: model.send_frozen
                frozenForReceiving: model.receive_frozen
            }
        }
    }

    // the default family of a label, to switch back from the fixed font
    M3Text { id: fontRef; visible: false }
}
