import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "controls"

// "Share Transaction" (export of a transaction) of the Material 3 GUI (M2-MAP F-1: full-screen dialog, created
// by PaymentFlow.showExport).
// repeats: components/ExportTxDialog.qml:8-130 @ e6df7e1c8 (the API text, text_qr, text_help, text_warn, tx_label;
// the QR code of text_qr rendered once the dialog has opened, the help and warning texts, Copy with "Copied!",
// Share by AppController.doShare, the buttons of plugins: app.pluginsComponentsByName('export_tx_button'),
// each created with { dialog: dialog } and laid out with the other buttons; the plugin reads dialog.text,
// dialog.tx_label and may call dialog.close()).
// Differences: Material 3 look; the buttons of the plugins are created when the dialog is completed (the classic
// DialogButtonContainer did it in its beforeLayout()); the QR code is as large as the width allows and, when
// the visible height is shorter than the code (landscape), scaled down to it.
// Strings keep the translation context of the classic file (qsTranslate('ExportTxDialog', ...)).
M3FullScreenDialog {
    id: dialog

    required property string text
    property string text_qr
    // if text_qr is undefined text will be used
    property string text_help
    property string text_warn
    property string tx_label

    title: qsTranslate('ExportTxDialog', 'Share Transaction')

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            id: flickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentHeight: content.implicitHeight + 2 * m3.space16
            interactive: height < contentHeight
            boundsBehavior: Flickable.StopAtBounds

            ColumnLayout {
                id: content
                readonly property int margin: m3.screenMargin(dialog.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
                spacing: m3.space16

                // the QR code on a card, centered (ExportTxDialog.qml:42-57)
                // (M3QRImage sets its width/height, not an implicit size, so the card is sized here)
                // On a short screen (the landscape Fold, 830x620) the card is scaled down to the visible
                // height, so the whole code is seen without scrolling; elsewhere the scale is 1.
                Item {
                    id: qrBox
                    readonly property real fit: Math.max(0.5, Math.min(1,
                        (flickable.height - 2 * m3.space16) / qrCard.implicitHeight))
                    Layout.alignment: Qt.AlignHCenter
                    implicitWidth: qrCard.implicitWidth * fit
                    implicitHeight: qrCard.implicitHeight * fit

                    Rectangle {
                        id: qrCard
                        width: implicitWidth
                        height: implicitHeight
                        implicitWidth: qr.width + 2 * m3.space16
                        implicitHeight: qr.height + 2 * m3.space16
                        transformOrigin: Item.TopLeft
                        scale: qrBox.fit
                        radius: m3.radiusL
                        color: m3.surfaceContainerLow

                        M3QRImage {
                            id: qr
                            anchors.centerIn: parent
                            qrdata: dialog.text_qr
                        }
                    }
                }

                M3InfoText {
                    Layout.fillWidth: true
                    visible: dialog.text_help
                    text: dialog.text_help
                }

                M3InfoText {
                    Layout.fillWidth: true
                    visible: dialog.text_warn
                    text: dialog.text_warn
                    iconStyle: M3InfoText.IconStyle.Warn
                }
            }
        }

        // ExportTxDialog.qml:81-115
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: buttons.implicitHeight + 2 * m3.space16
            color: m3.surface

            RowLayout {
                id: buttons
                readonly property int margin: m3.screenMargin(dialog.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
                spacing: m3.space8

                M3Button {
                    id: copyButton
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    variant: 'tonal'
                    size: 56
                    text: qsTranslate('ExportTxDialog', 'Copy')
                    icon.source: Qt.resolvedUrl('../../icons/m3/content_copy.png')
                    onClicked: {
                        AppController.textToClipboard(dialog.text)
                        toaster.show(this, qsTranslate('ExportTxDialog', 'Copied!'))
                    }
                }
                M3Button {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    variant: 'filled'
                    size: 56
                    text: qsTranslate('ExportTxDialog', 'Share')
                    icon.source: Qt.resolvedUrl('../../icons/m3/share.png')
                    onClicked: {
                        AppController.doShare(dialog.text, dialog.title)
                    }
                }

                // ExportTxDialog.qml:104-114
                function addPluginButtons() {
                    var export_tx_buttons = app.pluginsComponentsByName('export_tx_button')
                    for (var i=0; i < export_tx_buttons.length; i++) {
                        var b = export_tx_buttons[i].createObject(buttons, {
                            dialog: dialog
                        })
                        b.Layout.fillWidth = true
                        b.Layout.preferredWidth = 1
                    }
                }
                Component.onCompleted: addPluginButtons()
            }
        }
    }

    M3Toaster {
        id: toaster
    }

    // ExportTxDialog.qml:122-129: the QR code is rendered once the dialog has opened
    onOpened: qr.render = true
}
