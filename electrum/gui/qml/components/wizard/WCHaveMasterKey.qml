import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import "../controls"

WizardComponent {
    id: root

    valid: false

    function apply() {
        wizard_data['master_key'] = masterkey_ta.text
    }

    function verifyMasterKey(key) {
        return valid = bitcoin.verify_master_key(key)
    }

    ColumnLayout {
        width: parent.width

        Label { text: qsTr('Create keystore from a master key') }

        RowLayout {
            TextArea {
                id: masterkey_ta
                Layout.fillWidth: true
                Layout.minimumHeight: 80
                focus: true
                wrapMode: TextEdit.WrapAnywhere
                onTextChanged: verifyMasterKey(text)
            }
            ColumnLayout {
                ToolButton {
                    icon.source: '../../../icons/paste.png'
                    icon.height: constants.iconSizeMedium
                    icon.width: constants.iconSizeMedium
                    onClicked: {
                        if (verifyMasterKey(AppController.clipboardToText()))
                            masterkey_ta.text = AppController.clipboardToText()
                    }
                }
                ToolButton {
                    icon.source: '../../../icons/qrcode.png'
                    icon.height: constants.iconSizeMedium
                    icon.width: constants.iconSizeMedium
                    scale: 1.2
                    onClicked: {
                        var scan = qrscan.createObject(root)
                        scan.onFound.connect(function() {
                            if (verifyMasterKey(scan.scanData))
                                masterkey_ta.text = scan.scanData
                            scan.destroy()
                        })
                    }
                }
            }
        }
    }

    Component {
        id: qrscan
        QRScan {
            width: root.width
            height: root.height

            ToolButton {
                icon.source: '../../../icons/closebutton.png'
                icon.height: constants.iconSizeMedium
                icon.width: constants.iconSizeMedium
                anchors.right: parent.right
                anchors.top: parent.top
                onClicked: {
                    parent.destroy()
                }
            }
        }
    }

    Bitcoin {
        id: bitcoin
    }
}
