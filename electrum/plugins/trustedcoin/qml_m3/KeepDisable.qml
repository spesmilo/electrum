import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../../../gui/qml/components_m3/wizard"
import "../../../gui/qml/components_m3/controls"

// Material 3 page of the trustedcoin (2FA) wizard: keep or disable 2FA of a restored 2FA wallet. Loaded only by the
// Material 3 wizard (table _m3PluginPages of components_m3/wizard/Wizard.qml).
// repeats: plugins/trustedcoin/qml/KeepDisable.qml:7-34 (valid, apply(), the ButtonGroup calling
// checkIsLast() on every change, the two options with their `keepordisable`, the first checked).
// Look: the heading, the options as M3RadioRow in an M3ListGroup.
// Strings carried over keep the translation context of KeepDisable.qml.
WizardComponent {
    valid: keepordisablegroup.checkedButton

    function apply() {
        wizard_data['trustedcoin_keepordisable'] = keepordisablegroup.checkedButton.keepordisable
    }

    ButtonGroup {
        id: keepordisablegroup
        onCheckedButtonChanged: checkIsLast()
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
                text: qsTranslate('KeepDisable', 'Restore 2FA wallet')
            }

            M3ListGroup {
                Layout.fillWidth: true
                M3RadioRow {
                    ButtonGroup.group: keepordisablegroup
                    property string keepordisable: 'keep'
                    checked: true
                    text: qsTranslate('KeepDisable', 'Keep')
                }
                M3RadioRow {
                    ButtonGroup.group: keepordisablegroup
                    property string keepordisable: 'disable'
                    text: qsTranslate('KeepDisable', 'Disable')
                }
            }
        }
    }
}
