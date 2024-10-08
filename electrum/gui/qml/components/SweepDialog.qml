import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import org.electrum

import "controls"

ElDialog {
    id: root

    title: qsTr('Sweep private keys')
    iconSource: Qt.resolvedUrl('../../icons/sweep.png')

    property bool valid: false
    property string privateKeys

    width: parent.width
    height: parent.height
    padding: 0

    function verifyPrivateKey(key) {
        valid = false
        validationtext.text = ''
        key = key.trim()

        if (!key) {
            return false
        }

        if (!bitcoin.isPrivateKeyList(key)) {
            validationtext.text = qsTr('Error: invalid private key(s)')
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

        ColumnLayout {
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge

            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true

                RowLayout {
                    Layout.fillWidth: true
                    TextHighlightPane {
                        Layout.fillWidth: true
                        Label {
                            text: qsTr('Enter the list of private keys to sweep into this wallet')
                            wrapMode: Text.Wrap
                        }
                    }
                    HelpButton {
                        heading: qsTr('Sweep private keys')
                        helptext: qsTr('This will create a transaction sending all funds associated with the private keys to the current wallet') +
                        '<br/><br/>' + qsTr('WIF keys are typed in Electrum, based on script type.') + '<br/><br/>' +
                        qsTr('A few examples') + ':<br/>' +
                        '<tt><b>p2pkh</b>:KxZcY47uGp9a...       \t-> 1DckmggQM...<br/>' +
                        '<b>p2wpkh-p2sh</b>:KxZcY47uGp9a... \t-> 3NhNeZQXF...<br/>' +
                        '<b>p2wpkh</b>:KxZcY47uGp9a...      \t-> bc1q3fjfk...</tt>'
                    }
                }
                RowLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    ElTextArea {
                        id: sweepkeys
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        Layout.minimumHeight: 160
                        font.family: FixedFont
                        wrapMode: TextEdit.WrapAnywhere
                        onTextChanged: {
                            if (anyActiveFocus) {
                                verifyPrivateKey(text)
                            }
                        }
                        inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                        background: PaneInsetBackground {
                            baseColor: constants.darkerDialogBackground
                        }
                    }
                    ColumnLayout {
                        Layout.alignment: Qt.AlignTop
                        ToolButton {
                            icon.source: '../../icons/paste.png'
                            icon.height: constants.iconSizeMedium
                            icon.width: constants.iconSizeMedium
                            onClicked: {
                                if (verifyPrivateKey(AppController.clipboardToText()))
                                    addPrivateKey(AppController.clipboardToText())
                            }
                        }
                        ToolButton {
                            icon.source: '../../icons/qrcode.png'
                            icon.height: constants.iconSizeMedium
                            icon.width: constants.iconSizeMedium
                            scale: 1.2
                            onClicked: {
                                var dialog = app.scanDialog.createObject(app, {
                                    hint: qsTr('Scan a private key')
                                })
                                dialog.onFound.connect(function() {
                                    if (verifyPrivateKey(dialog.scanData))
                                        addPrivateKey(dialog.scanData)
                                    dialog.close()
                                })
                                dialog.open()
                            }
                        }
                    }
                }

                InfoTextArea {
                    id: validationtext
                    iconStyle: InfoTextArea.IconStyle.Warn
                    Layout.fillWidth: true
                    Layout.margins: constants.paddingMedium
                    visible: text
                }
            }
        }

        FlatButton {
            Layout.fillWidth: true
            Layout.preferredWidth: 1
            enabled: valid
            icon.source: '../../icons/tab_send.png'
            text: qsTr('Sweep')
            onClicked: {
                console.log('sweeping')
                root.privateKeys = sweepkeys.text
                root.accept()
            }
        }

    }

    Bitcoin {
        id: bitcoin
    }
}
