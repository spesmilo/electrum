import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Dialog {
    id: passworddialog

    title: qsTr("Enter Password")

    property bool confirmPassword: false
    property string password
    property string infotext

    parent: Overlay.overlay
    modal: true
    x: (parent.width - width) / 2
    y: (parent.height - height) / 2
    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    header: GridLayout {
        columns: 2
        rowSpacing: 0

        Image {
            source: "../../../icons/lock.png"
            Layout.preferredWidth: constants.iconSizeXLarge
            Layout.preferredHeight: constants.iconSizeXLarge
            Layout.leftMargin: constants.paddingMedium
            Layout.topMargin: constants.paddingMedium
            Layout.bottomMargin: constants.paddingMedium
        }

        Label {
            text: title
            elide: Label.ElideRight
            Layout.fillWidth: true
            topPadding: constants.paddingXLarge
            bottomPadding: constants.paddingXLarge
            font.bold: true
            font.pixelSize: constants.fontSizeMedium
        }

        Rectangle {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingXXSmall
            Layout.rightMargin: constants.paddingXXSmall
            height: 1
            color: Qt.rgba(0,0,0,0.5)
        }
    }

    ColumnLayout {
        width: parent.width

        InfoTextArea {
            visible: infotext
            text: infotext
            Layout.preferredWidth: password_layout.width
        }

        GridLayout {
            id: password_layout
            columns: 2
            Layout.fillWidth: true
            Layout.margins: constants.paddingXXLarge

            Label {
                text: qsTr('Password')
            }

            TextField {
                id: pw_1
                echoMode: TextInput.Password
            }

            Label {
                text: qsTr('Password (again)')
                visible: confirmPassword
            }

            TextField {
                id: pw_2
                echoMode: TextInput.Password
                visible: confirmPassword
            }
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: constants.paddingXXLarge

            Button {
                text: qsTr("Ok")
                enabled: confirmPassword ? pw_1.text == pw_2.text : true
                onClicked: {
                    password = pw_1.text
                    passworddialog.accept()
                }
            }
            Button {
                text: qsTr("Cancel")
                onClicked: {
                    passworddialog.reject()
                }
            }
        }
    }

}
