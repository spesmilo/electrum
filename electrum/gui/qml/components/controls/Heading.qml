import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

RowLayout {
    id: root

    property string text
    property alias font: label.font

    Layout.fillWidth: true
    Layout.topMargin: constants.paddingMedium
    Layout.bottomMargin: constants.paddingMedium

    spacing: constants.paddingLarge

    Rectangle {
        color: constants.mutedForeground
        height: 1
        Layout.fillWidth: true
    }

    Label {
        id: label
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
