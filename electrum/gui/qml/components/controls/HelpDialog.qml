import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

ElDialog {
    id: dialog

    header: Item { }
    footer: Item { }

    property string text
    property string heading

    z: 1 // raise z so it also covers dialogs using overlay as parent

    anchors.centerIn: parent

    padding: 0
    needsSystemBarPadding: false

    width: parent.width * 4/5

    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    background: Rectangle {
        color: "transparent"
    }

    Pane {
        id: rootPane
        width: parent.width
        implicitHeight: rootLayout.height + topPadding + bottomPadding
        padding: constants.paddingLarge
        background: Rectangle {
            color: constants.lighterBackground
        }
        ColumnLayout {
            id: rootLayout
            width: parent.width
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
            Item {
                height: constants.paddingLarge
            }
        }
    }
}
