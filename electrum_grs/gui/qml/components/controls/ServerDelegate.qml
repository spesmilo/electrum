import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

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
            rightMargin: constants.paddingSmall
        }

        columns: 3

        // topmargin
        Rectangle {
            Layout.columnSpan: 3
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
                source: '../../../icons/status_connected.png'
                width: constants.iconSizeMedium
                height: constants.iconSizeMedium
                visible: model.is_connected
            }
        }
        Label {
            Layout.fillWidth: true
            text: model.address
        }

        // bottommargin
        Rectangle {
            Layout.columnSpan: 3
            Layout.preferredHeight: constants.paddingSmall
            color: 'transparent'
        }
    }
}
