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
            leftMargin: constants.paddingSmall
            rightMargin: constants.paddingSmall
        }
        columns: 2
        Label {
            text: model.address
        }
        Label {
            text: model.chain
        }
    }
}
