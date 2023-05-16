import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import "controls"

ElDialog {
    id: dialog

    property string text
    property string text_qr
    // if text_qr is undefined text will be used
    property string text_help

    title: ''

    width: parent.width
    height: parent.height

    padding: 0

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.fillHeight: true
            Layout.fillWidth: true

            contentHeight: rootLayout.height
            clip:true
            interactive: height < contentHeight

            ColumnLayout {
                id: rootLayout
                width: parent.width
                spacing: constants.paddingMedium

                QRImage {
                    id: qr
                    render: dialog.enter ? false : true
                    qrdata: dialog.text_qr ? dialog.text_qr : dialog.text
                    Layout.alignment: Qt.AlignHCenter
                    Layout.topMargin: constants.paddingSmall
                    Layout.bottomMargin: constants.paddingSmall
                }

                TextHighlightPane {
                    Layout.leftMargin: constants.paddingMedium
                    Layout.rightMargin: constants.paddingMedium
                    Layout.fillWidth: true
                    visible: dialog.text
                    Label {
                        width: parent.width
                        text: dialog.text
                        wrapMode: Text.Wrap
                        font.pixelSize: constants.fontSizeLarge
                        font.family: FixedFont
                        maximumLineCount: 4
                        elide: Text.ElideRight
                    }
                }

                InfoTextArea {
                    Layout.leftMargin: constants.paddingMedium
                    Layout.rightMargin: constants.paddingMedium
                    visible: dialog.text_help
                    text: dialog.text_help
                    Layout.fillWidth: true
                }
            }
        }

        ButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1

                text: qsTr('Copy')
                icon.source: '../../icons/copy_bw.png'
                onClicked: {
                    AppController.textToClipboard(dialog.text)
                    toaster.show(this, qsTr('Copied!'))
                }
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1

                text: qsTr('Share')
                icon.source: '../../icons/share.png'
                onClicked: {
                    AppController.doShare(dialog.text, dialog.title)
                }
            }
        }
    }

    Connections {
        target: dialog.enter
        function onRunningChanged() {
            if (!dialog.enter.running) {
                qr.render = true
            }
        }
    }

    Toaster {
        id: toaster
    }
}
