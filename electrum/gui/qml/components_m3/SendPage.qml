import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// Send: the recipient input of the Material 3 GUI (replaces the classic SendDialog).
// repeats: components/SendDialog.qml:70-85, 103-105, 115-147, 173-202 @ 4f36c4489 (restart, dispatch, scanner
// hint, Paste, manual entry); the camera is not opened by itself: "Scan" opens the classic ScanDialog.
// Parsing, its errors and the next screen are those of PaymentFlow (the classic PIResolver / InvoiceParser).
// Contract towards PaymentFlow (as SendDialog): restart(); the page is taken off the stack by PaymentFlow.
// Strings carried over from SendDialog.qml keep its translation context (qsTranslate('SendDialog', ...)).
M3Page {
    id: root

    readonly property bool m3SendPage: true
    property QtObject flow  // PaymentFlow, set on creation

    // N-2: the field is locked while a recipient is resolved (bound to the busy state of the parsers)
    readonly property bool busy: flow !== null
        && (flow.piResolver.busy || flow.invoiceParser.busy || flow.requestDetails.busy)

    title: qsTranslate('WalletMainView', 'Send')

    // after a parse error (PaymentFlow.restartSendDialog): the entered text stays for correction
    function restart() {
        clipboardMessage.text = ''
        recipient.forceActiveFocus()
    }

    function submit(text) {
        clipboardMessage.text = ''
        // release focus, so the keyboard does not stay over the next screen (SendDialog.qml:176-180)
        root.forceActiveFocus()
        Qt.inputMethod.hide()
        flow.dispatch(text)
    }

    StackView.onRemoved: {
        if (flow && flow._sendDialog === root)
            flow._sendDialog = null
    }

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
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
                spacing: m3.space16

                // at most 6 lines of the field's font: a longer text (a PSBT) scrolls inside
                // the field, so the buttons below do not move away under the finger
                FontMetrics {
                    id: recipientMetrics
                    font: recipient.font
                }
                ScrollView {
                    id: recipientScroll
                    readonly property real _pads: recipient.topPadding + recipient.bottomPadding
                    Layout.fillWidth: true
                    Layout.preferredHeight: Math.max(3 * m3.textStyle('bodyLarge').line + _pads,
                        Math.min(recipient.implicitHeight, 6 * recipientMetrics.lineSpacing + _pads))

                    TextArea {
                        id: recipient
                        Material.containerStyle: Material.Outlined
                        placeholderText: qsTranslate('SendDialog', 'Recipient')
                        font.family: FixedFont
                        font.pixelSize: m3.textStyle('bodyLarge').size
                        color: m3.surfaceOn
                        wrapMode: TextEdit.WrapAnywhere
                        enabled: !root.busy
                        inputMethodHints: Qt.ImhEmailCharactersOnly | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                        // no automatic focus: the keyboard opens only when the user taps the field
                        focus: false
                        Keys.onReturnPressed: (event) => {
                            if (recipient.text.trim())
                                root.submit(recipient.text)
                        }
                        Keys.onEnterPressed: (event) => {
                            if (recipient.text.trim())
                                root.submit(recipient.text)
                        }
                        onTextChanged: clipboardMessage.text = ''
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: m3.space8

                    M3Button {
                        variant: 'tonal'
                        enabled: !root.busy
                        icon.source: Qt.resolvedUrl('../../icons/m3/content_paste.png')
                        text: qsTranslate('SendDialog', 'Paste')
                        onClicked: {
                            // the clipboard is read only on this button (Android shows a notice on reading)
                            var cliptext = AppController.clipboardToText().trim()
                            if (!cliptext) {
                                clipboardMessage.text = qsTranslate('SendDialog', 'Clipboard is empty')
                                return
                            }
                            recipient.text = cliptext
                            root.submit(cliptext)
                        }
                    }
                    M3Button {
                        variant: 'tonal'
                        enabled: !root.busy
                        icon.source: Qt.resolvedUrl('../../icons/m3/qr_code_scanner.png')
                        text: qsTr('Scan')
                        onClicked: {
                            clipboardMessage.text = ''
                            flow.scanRecipient(function(data) {
                                recipient.text = data.trim()
                            })
                        }
                    }
                    Item { Layout.fillWidth: true }
                }

                M3Text {
                    id: clipboardMessage
                    Layout.fillWidth: true
                    Layout.leftMargin: m3.space16
                    visible: text !== ''
                    role: 'bodySmall'
                    color: m3.error
                    wrapMode: Text.Wrap
                    lineHeightMode: Text.ProportionalHeight
                    lineHeight: 1.0
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.leftMargin: m3.space16
                    spacing: m3.space12
                    visible: root.busy

                    BusyIndicator {
                        Layout.preferredWidth: 24
                        Layout.preferredHeight: 24
                        running: root.busy
                    }
                    M3Text {
                        Layout.fillWidth: true
                        role: 'bodyMedium'
                        color: m3.surfaceVariantOn
                        wrapMode: Text.Wrap
                        lineHeightMode: Text.ProportionalHeight
                        lineHeight: 1.0
                        text: qsTr('Checking the recipient...')
                    }
                }

                M3Card {
                    Layout.fillWidth: true
                    color: m3.surfaceContainerLow

                    RowLayout {
                        width: parent.width
                        spacing: m3.space16
                        M3Icon {
                            Layout.alignment: Qt.AlignTop
                            source: Qt.resolvedUrl('../../icons/m3/info.png')
                            color: m3.surfaceVariantOn
                        }
                        M3Text {
                            Layout.fillWidth: true
                            role: 'bodyMedium'
                            color: m3.surfaceVariantOn
                            wrapMode: Text.Wrap
                            lineHeightMode: Text.ProportionalHeight
                            lineHeight: 1.0
                            text: flow ? flow.scanHint() : ''
                        }
                    }
                }
            }
        }

        // the main action stays below the content, above the keyboard (the page shrinks with the keyboard)
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: actions.implicitHeight + 2 * m3.space16
            color: m3.surface

            RowLayout {
                id: actions
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)

                Item { Layout.fillWidth: true }
                M3Button {
                    variant: 'filled'
                    size: 40
                    text: qsTranslate('ServerConnectWizard', 'Next')
                    enabled: recipient.text.trim() !== '' && !root.busy
                    onClicked: root.submit(recipient.text)
                }
            }
        }
    }
}
