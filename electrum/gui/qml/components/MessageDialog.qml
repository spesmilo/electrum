import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import "controls"

ElDialog {
    id: dialog
    title: qsTr("Message")
    iconSource: yesno
        ? Qt.resolvedUrl('../../icons/question.png')
        : Qt.resolvedUrl('../../icons/info.png')

    property bool yesno: false
    property alias text: message.text
    property bool richText: false

    signal yesClicked

    parent: Overlay.overlay
    modal: true
    z: 1 // raise z so it also covers dialogs using overlay as parent

    anchors.centerIn: parent

    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    padding: 0

    ColumnLayout {
        ColumnLayout {
            Layout.margins: constants.paddingMedium
            Layout.alignment: Qt.AlignHCenter
            TextArea {
                id: message
                Layout.preferredWidth: Overlay.overlay.width *2/3
                readOnly: true
                wrapMode: TextInput.WordWrap
                textFormat: richText ? TextEdit.RichText : TextEdit.PlainText
                background: Rectangle {
                    color: 'transparent'
                }
            }
        }

        ButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                textUnderIcon: false
                text: qsTr('Ok')
                icon.source: Qt.resolvedUrl('../../icons/confirmed.png')
                visible: !yesno
                onClicked: dialog.close()
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                textUnderIcon: false
                text: qsTr('Yes')
                icon.source: Qt.resolvedUrl('../../icons/confirmed.png')
                visible: yesno
                onClicked: {
                    yesClicked()
                    dialog.close()
                }
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                textUnderIcon: false
                text: qsTr('No')
                icon.source: Qt.resolvedUrl('../../icons/closebutton.png')
                visible: yesno
                onClicked: {
                    reject()
                    dialog.close()
                }
            }
        }
    }
}
