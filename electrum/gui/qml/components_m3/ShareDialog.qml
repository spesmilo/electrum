import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "controls"

// "Share" dialog of the Material 3 GUI: the type of the app.genericShareDialog factory (M2-MAP F-1: a full-screen
// dialog, the callers keep the classic API).
// repeats: components/GenericShareDialog.qml:8-131 @ e6df7e1c8 (the API: title, text, text_qr, text_help,
// helpTextIconStyle (the values of InfoTextArea.IconStyle, which M3InfoText.IconStyle repeats in the same order),
// iconSource; the meaning of text / text_qr: text is shown and is the data of the QR code unless text_qr is set;
// only text_qr set -> the QR code without the string, Copy still copies it; the text shown in a fixed font, at
// most 4 lines; the QR code rendered once the enter animation has finished; Copy -> AppController.textToClipboard
// (text ? text : text_qr) with "Copied!"; Share -> AppController.doShare(text ? text : text_qr, title)).
// Differences: Material 3 look (as the Material 3 ExportTxDialog): the QR code on a card, scaled down on a short
// screen (landscape, down to a half) so the text and the help (a warning for a channel backup) fit below it, the
// rest scrolls (scroll indicator); Copy and Share in a bar at the bottom.
// Strings keep the translation context of the classic file (qsTranslate('GenericShareDialog', ...)).
M3FullScreenDialog {
    id: dialog

    property string text
    property string text_qr
    // If text is set, it is displayed as a string and also used as data in the QR code shown.
    // text_qr can also be set if we want to show different data in the QR code.
    // If only text_qr is set, the QR code is shown but the string itself is not,
    //     however the copy button still exposes the string.

    property string text_help
    property int helpTextIconStyle: M3InfoText.IconStyle.Info

    title: ''

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

                // the QR code and the text on a card (GenericShareDialog.qml:45-78); on a short screen the
                // QR code is scaled down, so it is seen whole together with the text and the help
                Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: cardLayout.implicitHeight + 2 * m3.space16
                    radius: m3.radiusL
                    color: m3.surfaceContainerLow

                    ColumnLayout {
                        id: cardLayout
                        x: m3.space16
                        y: m3.space16
                        width: parent.width - 2 * m3.space16
                        spacing: m3.space16

                        Item {
                            id: qrBox
                            // the height left for the code: the visible height without the margins and paddings,
                            // the text below the code and the help (a warning for a channel backup) below the card
                            readonly property real _below: (textLine.visible ? textLine.implicitHeight + m3.space16 : 0)
                                + (helpText.visible ? helpText.implicitHeight + m3.space16 : 0)
                            readonly property real fit: Math.max(0.5, Math.min(1,
                                (flickable.height - 4 * m3.space16 - _below) / qr.height,
                                cardLayout.width / qr.width))
                            Layout.alignment: Qt.AlignHCenter
                            implicitWidth: qr.width * fit
                            implicitHeight: qr.height * fit

                            M3QRImage {
                                id: qr
                                transformOrigin: Item.TopLeft
                                scale: qrBox.fit
                                render: false
                                qrdata: dialog.text_qr ? dialog.text_qr : dialog.text
                            }
                        }

                        M3Text {
                            id: textLine
                            Layout.fillWidth: true
                            visible: dialog.text
                            role: 'bodyLarge'
                            font.family: FixedFont
                            wrapMode: Text.WrapAnywhere
                            maximumLineCount: 4
                            elide: Text.ElideRight
                            lineHeightMode: Text.ProportionalHeight
                            lineHeight: 1.0
                            horizontalAlignment: Text.AlignHCenter
                            text: dialog.text
                        }
                    }
                }

                M3InfoText {
                    id: helpText
                    Layout.fillWidth: true
                    iconStyle: dialog.helpTextIconStyle
                    visible: dialog.text_help
                    text: dialog.text_help
                }
            }

            ScrollIndicator.vertical: ScrollIndicator { }
        }

        // GenericShareDialog.qml:92-116
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
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    variant: 'tonal'
                    size: 56
                    text: qsTranslate('GenericShareDialog', 'Copy')
                    icon.source: Qt.resolvedUrl('../../icons/m3/content_copy.png')
                    onClicked: {
                        AppController.textToClipboard(dialog.text ? dialog.text : dialog.text_qr)
                        toaster.show(this, qsTranslate('GenericShareDialog', 'Copied!'))
                    }
                }
                M3Button {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    variant: 'filled'
                    size: 56
                    text: qsTranslate('GenericShareDialog', 'Share')
                    icon.source: Qt.resolvedUrl('../../icons/m3/share.png')
                    onClicked: {
                        AppController.doShare(dialog.text ? dialog.text : dialog.text_qr, dialog.title)
                    }
                }
            }
        }
    }

    // GenericShareDialog.qml:119-126: the QR code is rendered once the enter animation has finished
    onOpened: qr.render = true

    M3Toaster {
        id: toaster
    }
}
