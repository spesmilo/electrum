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
            rightMargin: constants.paddingSmall
        }

        columns: 2

        Rectangle {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            Layout.preferredHeight: constants.paddingTiny
            color: 'transparent'
        }

        Image {
            id: walleticon
            source: "../../../icons/lightning.png"
            fillMode: Image.PreserveAspectFit
            Layout.rowSpan: 3
            Layout.preferredWidth: constants.iconSizeLarge
            Layout.preferredHeight: constants.iconSizeLarge
            opacity: _closed ? 0.5 : 1.0

            Image {
                visible: model.is_trampoline
                source: "../../../icons/kangaroo.png"
                anchors {
                    right: parent.right
                    bottom: parent.bottom
                }
                width: parent.width * 2/3
                height: parent.height * 2/3
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Label {
                Layout.fillWidth: true
                text: model.node_alias
                elide: Text.ElideRight
                wrapMode: Text.Wrap
                maximumLineCount: 2
                color: _closed ? constants.mutedForeground : Material.foreground
            }

            Label {
                text: model.state
                color: _closed ? constants.mutedForeground : Material.foreground
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

        Item {
            id: chviz
            visible: !_closed
            Layout.fillWidth: true
            height: 10
            onWidthChanged: {
                var cap = model.capacity.satsInt * 1000
                var twocap = cap * 2
                b1.width = width * (cap - model.can_send.msatsInt) / twocap
                b2.width = width * model.can_send.msatsInt / twocap
                b3.width = width * model.can_receive.msatsInt / twocap
                b4.width = width * (cap - model.can_receive.msatsInt) / twocap
            }
            Rectangle {
                id: b1
                x: 0
                height: parent.height
                color: 'gray'
            }
            Rectangle {
                id: b2
                anchors.left: b1.right
                height: parent.height
                color: constants.colorLightningLocal
            }
            Rectangle {
                id: b3
                anchors.left: b2.right
                height: parent.height
                color: constants.colorLightningRemote
            }
            Rectangle {
                id: b4
                anchors.left: b3.right
                height: parent.height
                color: 'gray'
            }
        }
        Item {
            visible: _closed
            Layout.fillWidth: true
            height: 1
        }

        Rectangle {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            Layout.preferredHeight: constants.paddingTiny
            color: 'transparent'
        }

    }
}
