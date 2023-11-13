import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "controls"

ElDialog {
    id: dialog

    required property string text
    property string text_qr
    // if text_qr is undefined text will be used
    property string text_help
    property string text_warn

    title: qsTr('Share Transaction')

    width: parent.width
    height: parent.height

    padding: 0

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true

            contentHeight: rootLayout.height
            clip:true
            interactive: height < contentHeight

            ColumnLayout {
                id: rootLayout
                width: parent.width
                spacing: constants.paddingMedium

                TextHighlightPane {
                    Layout.fillWidth: true
                    Layout.leftMargin: constants.paddingMedium
                    Layout.rightMargin: constants.paddingMedium
                    padding: constants.paddingMedium
                    ColumnLayout {
                        width: parent.width
                        QRImage {
                            id: qr
                            qrdata: dialog.text_qr
                            Layout.alignment: Qt.AlignHCenter
                            Layout.topMargin: constants.paddingMedium
                            Layout.bottomMargin: constants.paddingMedium
                        }
                    }
                }

                InfoTextArea {
                    Layout.fillWidth: true
                    Layout.margins: constants.paddingLarge
                    visible: dialog.text_help
                    text: dialog.text_help
                }

                InfoTextArea {
                    Layout.fillWidth: true
                    Layout.margins: constants.paddingLarge
                    Layout.topMargin: dialog.text_help
                        ? 0
                        : constants.paddingLarge
                    visible: dialog.text_warn
                    text: dialog.text_warn
                    iconStyle: InfoTextArea.IconStyle.Warn
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

    Toaster {
        id: toaster
    }

    Connections {
        target: dialog.enter
        function onRunningChanged() {
            if (!dialog.enter.running) {
                qr.render = true
            }
        }
    }
}
