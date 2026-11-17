import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../controls"

// Material 3 page: how the next cosigner of a multisig wallet is added (its key or its seed).
// repeats: components/wizard/WCCosignerKeystore.qml:9-211 @ e6df7e1c8 (valid, cosigner, participants,
// multisigMasterPubkey from wizard_data; apply() putting the keystore type and the cosigner into wizard_data; the
// ButtonGroup with the two options and their `keystoretype`, the first checked; Component.onCompleted: the number of
// the cosigner from the cosigners already in wizard_data).
// Look (DESIGN-M2-onboarding.md 3.1): CosignerHeader (the master public key to share, as the classic block of
// this page, plus its line "Cosigner #%1 of %2"), the question as the heading, the options as M3RadioRow in an
// M3ListGroup.
// Strings carried over keep the translation context of WCCosignerKeystore.qml.
WizardComponent {
    id: root

    valid: keystoregroup.checkedButton !== null

    property int cosigner: 0
    property int participants: 0
    property string multisigMasterPubkey: wizard_data['multisig_master_pubkey']

    function apply() {
        wizard_data['cosigner_keystore_type'] = keystoregroup.checkedButton.keystoretype
        wizard_data['multisig_current_cosigner'] = cosigner
        wizard_data['multisig_cosigner_data'][cosigner.toString()] = {
            'keystore_type': keystoregroup.checkedButton.keystoretype
        }
    }

    ButtonGroup {
        id: keystoregroup
    }

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height + m3.space16
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: m3.space16

            CosignerHeader {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                pubkey: multisigMasterPubkey
                cosigner: root.cosigner
                participants: root.participants
            }

            M3Text {
                Layout.fillWidth: true
                Layout.topMargin: cosigner ? 0 : m3.space8
                role: 'titleMedium'
                wrapMode: Text.Wrap
                text: qsTranslate('WCCosignerKeystore', 'Add cosigner #%1 of %2 to your multi-sig wallet').arg(cosigner).arg(participants)
            }

            M3ListGroup {
                Layout.fillWidth: true
                M3RadioRow {
                    ButtonGroup.group: keystoregroup
                    property string keystoretype: 'masterkey'
                    checked: true
                    text: qsTranslate('WCCosignerKeystore', 'Cosigner key')
                }
                M3RadioRow {
                    ButtonGroup.group: keystoregroup
                    property string keystoretype: 'haveseed'
                    text: qsTranslate('WCCosignerKeystore', 'Cosigner seed')
                }
            }
        }
    }

    Component.onCompleted: {
        participants = wizard_data['multisig_participants']

        // cosigner index is determined here and put on the wizard_data dict in apply()
        // as this page is the start for each additional cosigner
        cosigner = 2 + Object.keys(wizard_data['multisig_cosigner_data']).length
    }
}
