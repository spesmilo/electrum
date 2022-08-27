import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1
import QtQuick.Controls.Material 2.0

GridLayout {
    property alias text: infotext.text

    enum IconStyle {
        None,
        Info,
        Warn,
        Error
    }

    property int iconStyle: InfoTextArea.IconStyle.Info
    property alias textFormat: infotext.textFormat

    columns: 1
    rowSpacing: 0

    Rectangle {
        height: 2
        Layout.fillWidth: true
        color: Qt.rgba(1,1,1,0.25)
    }

    TextArea {
        id: infotext
        Layout.fillWidth: true
        Layout.minimumHeight: constants.iconSizeLarge + 2*constants.paddingLarge
        readOnly: true
        rightPadding: constants.paddingLarge
        leftPadding: 2*constants.iconSizeLarge
        wrapMode: TextInput.Wrap
        textFormat: TextEdit.RichText
        background: Rectangle {
            color: Qt.rgba(1,1,1,0.05) // whiten 5%
        }

        Image {
            source: iconStyle == InfoTextArea.IconStyle.Info ? "../../../icons/info.png" : iconStyle == InfoTextArea.IconStyle.Warn ? "../../../icons/warning.png" : iconStyle == InfoTextArea.IconStyle.Error ? "../../../icons/expired.png" : ""
            anchors.left: parent.left
            anchors.top: parent.top
            anchors.leftMargin: constants.paddingLarge
            anchors.topMargin: constants.paddingLarge
            height: constants.iconSizeLarge
            width: constants.iconSizeLarge
            fillMode: Image.PreserveAspectCrop
        }

    }

    Rectangle {
        height: 2
        Layout.fillWidth: true
        color: Qt.rgba(0,0,0,0.25)
    }
}
