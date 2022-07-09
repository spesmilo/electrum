import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

ItemDelegate {
    id: root
    height: item.height
    width: ListView.view.width

    font.pixelSize: constants.fontSizeSmall // set default font size for child controls

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
        }

        RowLayout {
            Layout.fillWidth: true
            Label {
                Layout.fillWidth: true
                text: model.node_alias
                elide: Text.ElideRight
                wrapMode: Text.Wrap
                maximumLineCount: 2
            }

            Label {
                text: model.state
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
            }

            Label {
                text: Config.baseUnit
                color: Material.accentColor
            }
        }

        Item {
            id: chviz
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
        Rectangle {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            Layout.preferredHeight: constants.paddingTiny
            color: 'transparent'
        }

    }
}
