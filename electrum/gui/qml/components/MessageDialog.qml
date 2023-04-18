import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import "controls"

ElDialog {
    id: dialog
    title: yesno ? qsTr("Question") : qsTr("Message")
    iconSource: yesno
        ? Qt.resolvedUrl('../../icons/question.png')
        : Qt.resolvedUrl('../../icons/info.png')

    property bool yesno: false
    property alias text: message.text
    property bool richText: false

    z: 1 // raise z so it also covers dialogs using overlay as parent

    anchors.centerIn: parent

    padding: 0

    ColumnLayout {
        ColumnLayout {
            visible: text
            Layout.margins: constants.paddingMedium
            Layout.alignment: Qt.AlignHCenter
            TextArea {
                id: message
                Layout.preferredWidth: dialog.parent.width * 2/3
                readOnly: true
                wrapMode: TextInput.WordWrap
                textFormat: richText ? TextEdit.RichText : TextEdit.PlainText
                background: Rectangle {
                    color: 'transparent'
                }
            }
        }

        ButtonContainer {
            Layout.preferredWidth: dialog.parent.width * 2/3

            FlatButton {
                Layout.fillWidth: true
                textUnderIcon: false
                text: qsTr('Ok')
                icon.source: Qt.resolvedUrl('../../icons/confirmed.png')
                visible: !yesno
                onClicked: doAccept()
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                textUnderIcon: false
                text: qsTr('No')
                icon.source: Qt.resolvedUrl('../../icons/closebutton.png')
                visible: yesno
                onClicked: doReject()
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                textUnderIcon: false
                text: qsTr('Yes')
                icon.source: Qt.resolvedUrl('../../icons/confirmed.png')
                visible: yesno
                onClicked: doAccept()
            }
        }
    }
}
