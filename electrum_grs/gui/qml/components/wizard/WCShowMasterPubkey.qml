import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import "../controls"

WizardComponent {
    valid: true

    property string masterPubkey: ''

    ColumnLayout {
        width: parent.width

        Label {
            text: qsTr('Here is your master public key. Please share it with your cosigners')
            Layout.fillWidth: true
            wrapMode: Text.Wrap
        }

        TextHighlightPane {
            Layout.fillWidth: true
            padding: 0
            leftPadding: constants.paddingSmall

            RowLayout {
                width: parent.width
                Label {
                    Layout.fillWidth: true
                    text: masterPubkey
                    font.pixelSize: constants.fontSizeMedium
                    font.family: FixedFont
                    wrapMode: Text.Wrap
                }
                ToolButton {
                    icon.source: '../../../icons/share.png'
                    icon.color: 'transparent'
                    onClicked: {
                        var dialog = app.genericShareDialog.createObject(app,
                            { title: qsTr('Master public key'), text: masterPubkey }
                        )
                        dialog.open()
                    }
                }
            }
        }
    }

    Bitcoin {
        id: bitcoin
    }

    Component.onCompleted: {
        if ('master_key' in wizard_data) {
            masterPubkey = bitcoin.getMultisigMasterPubkeyFromKey(wizard_data['master_key'])
        } else if (wizard_data['seed_variant'] == 'electrum') {
            masterPubkey = bitcoin.getMultisigMasterPubkeyFromSeed(wizard_data['seed_variant'], wizard_data['seed'], wizard_data['seed_extra_words'])
        } else {
            masterPubkey = bitcoin.getMultisigMasterPubkeyFromSeed(wizard_data['seed_variant'], wizard_data['seed'], wizard_data['seed_extra_words'], wizard_data['derivation_path'])
        }
    }
}
