import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

Dialog {
    id: dialog

    property string text

    title: ''
    parent: Overlay.overlay
    modal: true
    standardButtons: Dialog.Ok

    width: parent.width
    height: parent.height

    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    header: RowLayout {
        width: dialog.width
        Label {
            Layout.fillWidth: true
            text: dialog.title
            visible: dialog.title
            elide: Label.ElideRight
            padding: constants.paddingXLarge
            bottomPadding: 0
            font.bold: true
            font.pixelSize: constants.fontSizeMedium
        }
    }

    Flickable {
        anchors.fill: parent
        contentHeight: rootLayout.height
        clip:true
        interactive: height < contentHeight

        ColumnLayout {
            id: rootLayout
            width: parent.width
            spacing: constants.paddingMedium

            Rectangle {
                height: 1
                Layout.fillWidth: true
                color: Material.accentColor
            }

            Image {
                id: qr
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: constants.paddingSmall
                Layout.bottomMargin: constants.paddingSmall

                Rectangle {
                    property int size: 57 // should be qr pixel multiple
                    color: 'white'
                    x: (parent.width - size) / 2
                    y: (parent.height - size) / 2
                    width: size
                    height: size

                    Image {
                        source: '../../../icons/electrum.png'
                        x: 1
                        y: 1
                        width: parent.width - 2
                        height: parent.height - 2
                        scale: 0.9
                    }
                }
            }

            Rectangle {
                height: 1
                Layout.fillWidth: true
                color: Material.accentColor
            }

            TextHighlightPane {
                Layout.fillWidth: true
                Label {
                    width: parent.width
                    text: dialog.text
                    wrapMode: Text.Wrap
                    font.pixelSize: constants.fontSizeLarge
                    font.family: FixedFont
                }
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignHCenter
                Button {
                    text: qsTr('Copy')
                    icon.source: '../../../icons/copy_bw.png'
                    onClicked: AppController.textToClipboard(dialog.text)
                }
                Button {
                    //enabled: false
                    text: qsTr('Share')
                    icon.source: '../../../icons/share.png'
                    onClicked: {
                        AppController.doShare(dialog.text, dialog.title)
                    }
                }
            }
        }
    }

    Component.onCompleted: {
        qr.source = 'image://qrgen/' + dialog.text
    }
}
