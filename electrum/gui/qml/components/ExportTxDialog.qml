import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "controls"

ElDialog {
    id: dialog

    required property string psbt
    property string text_help
    property string tx_label

    property var _export: QRIP.getTxExportData(dialog.psbt)
    readonly property string text_warn: !_export.data_stripped
        ? ''
        : [qsTr('Warning: Some data (prev txs / "full utxos") was left out of the QR code to reduce its size.'),
           qsTr('This might cause issues if signing offline.'),
           qsTr('As a workaround, copy to clipboard or use the Share option instead.')].join(' ')

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

                DialogHighlightPane {
                    Layout.fillWidth: true
                    Layout.leftMargin: constants.paddingMedium
                    Layout.rightMargin: constants.paddingMedium
                    padding: constants.paddingMedium
                    ColumnLayout {
                        width: parent.width
                        QRImage {
                            id: qr
                            visible: !dialog._export.ur_payload
                            qrdata: dialog._export.qr_text
                            Layout.alignment: Qt.AlignHCenter
                            Layout.topMargin: constants.paddingMedium
                            Layout.bottomMargin: constants.paddingMedium
                        }
                        URQRImage {
                            visible: dialog._export.ur_payload
                            urType: dialog._export.ur_type
                            payload: dialog._export.ur_payload
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
                    backgroundColor: constants.darkerDialogBackground
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
                    backgroundColor: constants.darkerDialogBackground
                }
            }
        }

        DialogButtonContainer {
            id: buttons
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Copy')
                icon.source: '../../icons/copy_bw.png'
                onClicked: {
                    AppController.textToClipboard(dialog._export.text)
                    toaster.show(this, qsTr('Copied!'))
                }
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Share')
                icon.source: '../../icons/share.png'
                onClicked: {
                    AppController.doShare(dialog._export.text, dialog.title)
                }
            }
            function beforeLayout() {
                var export_tx_buttons = app.pluginsComponentsByName('export_tx_button')
                for (var i=0; i < export_tx_buttons.length; i++) {
                    var b = export_tx_buttons[i].createObject(buttons, {
                        dialog: dialog
                    })
                    b.Layout.fillWidth = true
                    b.Layout.preferredWidth = 1
                    buttons.addItem(b)
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
