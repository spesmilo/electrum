import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

ItemDelegate {
    id: root
    height: item.height
    width: ListView.view.width

    font.pixelSize: constants.fontSizeSmall // set default font size for child controls

    property bool _closed: model.state_code == ChannelDetails.Closed
                            || model.state_code == ChannelDetails.Redeemed

    GridLayout {
        id: item

        anchors {
            left: parent.left
            right: parent.right
            leftMargin: constants.paddingSmall
            rightMargin: constants.paddingMedium
        }

        columns: 2

        Rectangle {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            Layout.preferredHeight: constants.paddingXXSmall
            color: 'transparent'
        }

        Image {
            id: walleticon
            source: model.is_backup
                        ? model.is_imported
                            ? '../../../icons/cloud_no.png'
                            : '../../../icons/lightning_disconnected.png'
                        : model.is_trampoline
                            ? '../../../icons/kangaroo.png'
                            : '../../../icons/lightning.png'
            fillMode: Image.PreserveAspectFit
            Layout.rowSpan: 3
            Layout.preferredWidth: constants.iconSizeLarge
            Layout.preferredHeight: constants.iconSizeLarge
            opacity: _closed ? 0.5 : 1.0

            Image {
                visible: model.is_trampoline
                source: '../../../icons/lightning.png'
                anchors {
                    right: parent.right
                    bottom: parent.bottom
                }
                width: parent.width * 1/3
                height: parent.height * 1/3
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Label {
                Layout.fillWidth: true
                text: model.node_alias ? model.node_alias : model.node_id
                font.family: model.node_alias ? app.font.family : FixedFont
                font.pixelSize: model.node_alias ? constants.fontSizeMedium : constants.fontSizeSmall
                elide: Text.ElideRight
                wrapMode: Text.Wrap
                maximumLineCount: model.node_alias ? 2 : 1
                color: _closed ? constants.mutedForeground : Material.foreground
            }

            Label {
                text: model.state
                font.pixelSize: constants.fontSizeMedium
                color: _closed
                        ? constants.mutedForeground
                        : model.state == 'OPEN'
                            ? constants.colorChannelOpen
                            : Material.foreground
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Label {
                Layout.fillWidth: true
                text: model.short_cid
                color: constants.mutedForeground
            }

            Label {
                text: Config.formatSats(model.capacity)
                font.family: FixedFont
                color: _closed ? constants.mutedForeground : Material.foreground
            }

            Label {
                text: Config.baseUnit
                color: _closed ? constants.mutedForeground : Material.accentColor
            }
        }

        ChannelBar {
            Layout.fillWidth: true
            visible: !_closed && !model.is_backup
            capacity: model.capacity
            localCapacity: model.local_capacity
            remoteCapacity: model.remote_capacity
        }

        Item {
            visible: _closed
            Layout.fillWidth: true
            height: 1
        }

        Item {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            Layout.preferredHeight: constants.paddingXXSmall
        }

    }
}
