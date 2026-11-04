import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Controls.Material

import org.electrum 1.0

ItemDelegate {
    id: root
    height: itemLayout.height
    width: ListView.view.width

    GridLayout {
        id: itemLayout
        anchors {
            left: parent.left
            right: parent.right
            leftMargin: constants.paddingXLarge
            rightMargin: constants.paddingSmall + (root.ListView.view.rightExclusionZone || 0)
        }

        columns: 4

        // topmargin
        Rectangle {
            Layout.columnSpan: 4
            Layout.preferredHeight: constants.paddingSmall
            color: 'transparent'
        }

        Item {
            Layout.preferredWidth: constants.iconSizeMedium
            Layout.preferredHeight: constants.iconSizeMedium
            Image {
                source: '../../../icons/chevron-right.png'
                width: constants.iconSizeMedium
                height: constants.iconSizeMedium
                visible: model.is_primary
            }
        }
        Item {
            Layout.preferredWidth: constants.iconSizeMedium
            Layout.preferredHeight: constants.iconSizeMedium
            Image {
                source: model.is_lagging
                    ? '../../../icons/status_lagging.png'
                    : '../../../icons/status_connected.png'
                width: constants.iconSizeMedium
                height: constants.iconSizeMedium
                visible: model.is_connected
            }
        }
        Label {
            Layout.fillWidth: true
            text: model.address
            wrapMode: Text.Wrap
        }
        Item {
            Layout.preferredWidth: constants.iconSizeLarge
            Layout.preferredHeight: constants.iconSizeLarge
            Image {
                anchors.centerIn: parent
                width: constants.iconSizeMedium
                height: constants.iconSizeMedium
                source: model.is_bookmarked
                    ? '../../../icons/bookmark.png'
                    : '../../../icons/bookmark_add.png'
                opacity: model.is_bookmarked ? 1.0 : 0.4
            }
            MouseArea {
                anchors.fill: parent
                onClicked: Network.setServerBookmark(model.name, !model.is_bookmarked)
            }
        }

        // bottommargin
        Rectangle {
            Layout.columnSpan: 4
            Layout.preferredHeight: constants.paddingSmall
            color: 'transparent'
        }
    }
}
