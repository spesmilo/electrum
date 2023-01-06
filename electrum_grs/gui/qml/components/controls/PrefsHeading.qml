import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

RowLayout {
    id: root

    property string text

    Layout.fillWidth: true
    Layout.topMargin: constants.paddingXLarge

    spacing: constants.paddingLarge

    Rectangle {
        color: constants.mutedForeground
        height: 1
        Layout.fillWidth: true
    }

    Label {
        Layout.leftMargin: constants.paddingMedium
        Layout.rightMargin: constants.paddingMedium
        text: root.text
        color: constants.mutedForeground
        font.pixelSize: constants.fontSizeLarge
    }

    Rectangle {
        color: constants.mutedForeground
        height: 1
        Layout.fillWidth: true
    }

}
