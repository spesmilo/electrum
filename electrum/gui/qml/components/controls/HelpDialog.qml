import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

ElDialog {
    id: dialog

    header: Item { }

    property string text
    property string heading

    z: 1 // raise z so it also covers dialogs using overlay as parent

    anchors.centerIn: parent

    padding: 0

    width: rootPane.width

    Overlay.modal: Rectangle {
        color: "#55000000"
    }

    Pane {
        id: rootPane
        width: rootLayout.width + leftPadding + rightPadding
        padding: constants.paddingLarge

        ColumnLayout {
            id: rootLayout
            width: dialog.parent.width * 3/4
            spacing: constants.paddingLarge

            RowLayout {
                Layout.fillWidth: true
                Image {
                    source: Qt.resolvedUrl('../../../icons/info.png')
                    Layout.preferredWidth: constants.iconSizeSmall
                    Layout.preferredHeight: constants.iconSizeSmall
                }
                Label {
                    text: dialog.heading
                    font.pixelSize: constants.fontSizeMedium
                    font.underline: true
                    font.italic: true
                }
            }
            Label {
                id: message
                Layout.fillWidth: true
                text: dialog.text
                font.pixelSize: constants.fontSizeSmall
                wrapMode: TextInput.WordWrap
                textFormat: TextEdit.RichText
                background: Rectangle {
                    color: 'transparent'
                }
            }
        }
    }
}
