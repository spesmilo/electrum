import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../../../gui/qml/components_m3/wizard"
import "../../../gui/qml/components_m3/controls"

// Material 3 page of the trustedcoin (2FA) wizard: create a new seed or restore from an existing one. Loaded only by
// the Material 3 wizard (table _m3PluginPages of components_m3/wizard/Wizard.qml).
// repeats: plugins/trustedcoin/qml/ChooseSeed.qml:7-37 @ e6df7e1c8 (valid; the keystore type put into wizard_data by
// an onAccept handler (not apply(): beside the onAccept -> apply() of the base, as the classic page); the
// ButtonGroup with the two options and their `keystoretype`, the first checked).
// Look (DESIGN-M2-onboarding.md 4): the question as the heading, the options as M3RadioRow in an M3ListGroup.
// Strings carried over keep the translation context of ChooseSeed.qml.
WizardComponent {
    valid: keystoregroup.checkedButton !== null

    onAccept: {
        wizard_data['keystore_type'] = keystoregroup.checkedButton.keystoretype
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

            M3Text {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                role: 'titleMedium'
                wrapMode: Text.Wrap
                text: qsTranslate('ChooseSeed', 'Do you want to create a new seed, or restore a wallet using an existing seed?')
            }

            M3ListGroup {
                Layout.fillWidth: true
                M3RadioRow {
                    ButtonGroup.group: keystoregroup
                    property string keystoretype: 'createseed'
                    checked: true
                    text: qsTranslate('ChooseSeed', 'Create a new seed')
                }
                M3RadioRow {
                    ButtonGroup.group: keystoregroup
                    property string keystoretype: 'haveseed'
                    text: qsTranslate('ChooseSeed', 'I already have a seed')
                }
            }
        }
    }
}
