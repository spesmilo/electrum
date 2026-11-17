import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import org.electrum

import "controls"

// "Sweep private keys" of the Material 3 GUI (PaymentFlow.startSweep, wallet menu "Sweep key(s)"; M2-MAP F-1:
// a full-screen dialog that returns its result by `accepted`).
// repeats: components/SweepDialog.qml:9-172 @ e6df7e1c8 (the API: valid, privateKeys, accepted; verifyPrivateKey:
// the trimmed text is checked by Bitcoin.isPrivateKeyList, an invalid list shows "Error: invalid private key(s)";
// addPrivateKey appends a key on its own line unless it is already there; the text is verified on each change
// while the field has the focus; Paste verifies the clipboard and adds it; the scan button opens app.scanDialog
// with "Scan a private key", verifies and adds the data found and closes the scanner; the help (heading and text);
// "Sweep..." enabled when valid sets privateKeys to the text and accepts; the window is secure (no screenshots)
// while the dialog is visible).
// Differences: Material 3 look: the top bar of M3FullScreenDialog (X closes), M3TextArea, Paste and Scan as icon
// buttons next to the field, the error as an M3InfoText, "Sweep..." in a bar at the bottom.
// Strings keep the translation context of the classic file (qsTranslate('SweepDialog', ...)).
M3FullScreenDialog {
    id: root

    title: qsTranslate('SweepDialog', 'Sweep private keys')

    property bool valid: false
    property string privateKeys

    function verifyPrivateKey(key) {
        valid = false
        validationtext.text = ''
        key = key.trim()

        if (!key) {
            return false
        }

        if (!bitcoin.isPrivateKeyList(key)) {
            validationtext.text = qsTranslate('SweepDialog', 'Error: invalid private key(s)')
            return false
        }

        return valid = true
    }

    function addPrivateKey(key) {
        if (sweepkeys.text.includes(key))
            return
        if (sweepkeys.text && !sweepkeys.text.endsWith('\n'))
            sweepkeys.text = sweepkeys.text + '\n'
        sweepkeys.text = sweepkeys.text + key + '\n'
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            id: flickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            readonly property real _needed: content.implicitHeight + 2 * m3.space16
            contentHeight: Math.max(height, _needed)
            interactive: height < _needed
            boundsBehavior: Flickable.StopAtBounds

            ColumnLayout {
                id: content
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
                height: flickable.contentHeight - 2 * m3.space16
                spacing: m3.space16

                RowLayout {
                    Layout.fillWidth: true
                    spacing: m3.space8

                    M3Text {
                        Layout.fillWidth: true
                        role: 'bodyLarge'
                        wrapMode: Text.Wrap
                        lineHeightMode: Text.ProportionalHeight
                        lineHeight: 1.0
                        text: qsTranslate('SweepDialog', 'Enter the list of private keys to sweep into this wallet')
                    }
                    M3HelpButton {
                        Layout.alignment: Qt.AlignTop
                        heading: qsTranslate('SweepDialog', 'Sweep private keys')
                        helptext: qsTranslate('SweepDialog', 'This will create a transaction sending all funds associated with the private keys to the current wallet') +
                        '<br/><br/>' + qsTranslate('SweepDialog', 'WIF keys are typed in Electrum, based on script type.') + '<br/><br/>' +
                        qsTranslate('SweepDialog', 'A few examples') + ':<br/>' +
                        '<tt><b>p2pkh</b>:KxZcY47uGp9a...       \t-> 1DckmggQM...<br/>' +
                        '<b>p2wpkh-p2sh</b>:KxZcY47uGp9a... \t-> 3NhNeZQXF...<br/>' +
                        '<b>p2wpkh</b>:KxZcY47uGp9a...      \t-> bc1q3fjfk...</tt>'
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    spacing: m3.space4

                    M3TextArea {
                        id: sweepkeys
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        Layout.minimumHeight: 160
                        font.family: FixedFont
                        wrapMode: TextEdit.WrapAnywhere
                        errorText: validationtext.text
                        onTextChanged: {
                            if (anyActiveFocus) {
                                verifyPrivateKey(text)
                            }
                        }
                        inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                    }
                    ColumnLayout {
                        Layout.alignment: Qt.AlignTop
                        spacing: 0
                        M3IconButton {
                            tooltip: qsTr('Paste')
                            icon.source: Qt.resolvedUrl('../../icons/m3/content_paste.png')
                            onClicked: {
                                if (verifyPrivateKey(AppController.clipboardToText()))
                                    addPrivateKey(AppController.clipboardToText())
                            }
                        }
                        M3IconButton {
                            tooltip: qsTr('Scan QR code')
                            icon.source: Qt.resolvedUrl('../../icons/m3/qr_code_scanner.png')
                            onClicked: {
                                var dialog = app.scanDialog.createObject(app, {
                                    hint: qsTranslate('SweepDialog', 'Scan a private key')
                                })
                                dialog.onFoundText.connect(function(data) {
                                    if (verifyPrivateKey(data))
                                        addPrivateKey(data)
                                    dialog.close()
                                })
                                dialog.open()
                            }
                        }
                    }
                }

                M3InfoText {
                    id: validationtext
                    iconStyle: M3InfoText.IconStyle.Warn
                    Layout.fillWidth: true
                    visible: text
                }
            }
        }

        // SweepDialog.qml:143-159
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: sweepButton.implicitHeight + 2 * m3.space16
            color: m3.surface

            M3Button {
                id: sweepButton
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
                variant: 'filled'
                size: 56
                enabled: valid
                icon.source: Qt.resolvedUrl('../../icons/m3/send.png')
                text: qsTranslate('SweepDialog', 'Sweep...')
                onClicked: {
                    console.log('sweeping')
                    root.privateKeys = sweepkeys.text
                    root.accept()
                }
            }
        }
    }

    Bitcoin {
        id: bitcoin
    }

    Binding {
        target: AppController
        property: 'secureWindow'
        when: root.visible  // enables stacking multiple secureWindow dialogs
        value: true
    }
}
