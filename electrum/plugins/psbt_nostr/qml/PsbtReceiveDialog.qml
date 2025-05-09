import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "../../../gui/qml/components/controls"

ElDialog {
    id: dialog
    title: qsTr("PSBT received")
    iconSource: Qt.resolvedUrl('../../../gui/icons/question.png')

    enum Choice {
        None,
        Open,
        Save
    }

    property string tx_label
    property int choice: PsbtReceiveDialog.Choice.None

    // TODO: it might be better to defer popup until no dialogs are shown
    z: 1 // raise z so it also covers dialogs using overlay as parent

    anchors.centerIn: parent

    padding: 0

    width: rootLayout.width

    ColumnLayout {
        id: rootLayout
        width: dialog.parent.width * 2/3

        ColumnLayout {
            Layout.margins: constants.paddingMedium
            Layout.fillWidth: true

            TextArea {
                id: message
                Layout.fillWidth: true
                readOnly: true
                wrapMode: TextInput.WordWrap
                textFormat: TextEdit.RichText
                background: Rectangle {
                    color: 'transparent'
                }

                text: [
                    tx_label
                        ? qsTr('A transaction was received from your cosigner with label: <br/><b>%1</b><br/>').arg(tx_label)
                        : qsTr('A transaction was received from your cosigner.'),
                    qsTr('Do you want to open it now?')
                ].join('<br/>')
            }
        }

        ButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Open')
                icon.source: Qt.resolvedUrl('../../../gui/icons/confirmed.png')
                onClicked: {
                    choice = PsbtReceiveDialog.Choice.Open
                    doAccept()
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Discard')
                icon.source: Qt.resolvedUrl('../../../gui/icons/closebutton.png')
                onClicked: doReject()
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Save to Wallet')
                icon.source: Qt.resolvedUrl('../../../gui/icons/wallet.png')
                onClicked: {
                    choice = PsbtReceiveDialog.Choice.Save
                    doAccept()
                }
            }
        }
    }
}
