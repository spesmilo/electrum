import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import "controls"

ElDialog {
    id: dialog
    title: qsTr("Message")

    property bool yesno: false
    property alias text: message.text

    signal yesClicked
    signal noClicked

    parent: Overlay.overlay
    modal: true

    anchors.centerIn: parent

    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    ColumnLayout {
        TextArea {
            id: message
            Layout.preferredWidth: Overlay.overlay.width *2/3
            readOnly: true
            wrapMode: TextInput.WordWrap
            //textFormat: TextEdit.RichText // existing translations not richtext yet
            background: Rectangle {
                color: 'transparent'
            }
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            Button {
                text: qsTr('Ok')
                visible: !yesno
                onClicked: dialog.close()
            }
            Button {
                text: qsTr('Yes')
                visible: yesno
                onClicked: {
                    yesClicked()
                    dialog.close()
                }
            }
            Button {
                text: qsTr('No')
                visible: yesno
                onClicked: {
                    noClicked()
                    dialog.close()
                }
            }
        }
    }
}
