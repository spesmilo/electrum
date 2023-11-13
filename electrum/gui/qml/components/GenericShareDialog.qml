import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "controls"

ElDialog {
    id: dialog

    property string text
    property string text_qr
    // If text is set, it is displayed as a string and also used as data in the QR code shown.
    // text_qr can also be set if we want to show different data in the QR code.
    // If only text_qr is set, the QR code is shown but the string itself is not,
    //     however the copy button still exposes the string.

    property string text_help
    property int helpTextIconStyle: InfoTextArea.IconStyle.Info

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

                TextHighlightPane {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.fillWidth: true
                    Layout.leftMargin: constants.paddingMedium
                    Layout.rightMargin: constants.paddingMedium

                    ColumnLayout {
                        width: parent.width

                        QRImage {
                            id: qr
                            render: dialog.enter ? false : true
                            qrdata: dialog.text_qr ? dialog.text_qr : dialog.text
                            Layout.alignment: Qt.AlignHCenter
                            Layout.topMargin: constants.paddingMedium
                            Layout.bottomMargin: constants.paddingMedium
                        }

                        TextHighlightPane {
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
                    }
                }

                InfoTextArea {
                    Layout.leftMargin: constants.paddingMedium
                    Layout.rightMargin: constants.paddingMedium
                    iconStyle: helpTextIconStyle
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
                    AppController.textToClipboard(dialog.text ? dialog.text : dialog.text_qr)
                    toaster.show(this, qsTr('Copied!'))
                }
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1

                text: qsTr('Share')
                icon.source: '../../icons/share.png'
                onClicked: {
                    AppController.doShare(dialog.text ? dialog.text : dialog.text_qr, dialog.title)
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
