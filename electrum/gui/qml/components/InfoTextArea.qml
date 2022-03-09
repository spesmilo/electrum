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
        readOnly: true
        rightPadding: 16
        leftPadding: 64
        wrapMode: TextInput.WordWrap
        textFormat: TextEdit.RichText
        background: Rectangle {
            color: Qt.rgba(1,1,1,0.05) // whiten 5%
        }

        Image {
            source: iconStyle == InfoTextArea.IconStyle.Info ? "../../icons/info.png" : InfoTextArea.IconStyle.Warn ? "../../icons/warning.png" : InfoTextArea.IconStyle.Error ? "../../icons/expired.png" : ""
            anchors.left: parent.left
            anchors.top: parent.top
            anchors.leftMargin: 16
            anchors.topMargin: 16
            height: 32
            width: 32
            fillMode: Image.PreserveAspectCrop
        }

    }

    Rectangle {
        height: 2
        Layout.fillWidth: true
        color: Qt.rgba(0,0,0,0.25)
    }
}
