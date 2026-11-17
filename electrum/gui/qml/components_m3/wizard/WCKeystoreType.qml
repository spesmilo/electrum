import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

// Material 3 page: create a seed, restore from a seed or from a master key.
// repeats: components/wizard/WCKeystoreType.qml:7-53 @ e6df7e1c8 (valid, apply(), the ButtonGroup and the
// `keystoretype` of every option, the first option checked, the hidden disabled "hardware" option, the strings).
WizardComponent {
    valid: keystoregroup.checkedButton !== null

    function apply() {
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
                text: qsTranslate('WCKeystoreType', 'Do you want to create a new seed, restore using an existing seed, or restore from master key?')
            }

            M3ListGroup {
                Layout.fillWidth: true
                M3RadioRow {
                    ButtonGroup.group: keystoregroup
                    property string keystoretype: 'createseed'
                    checked: true
                    text: qsTranslate('WCKeystoreType', 'Create a new seed')
                }
                M3RadioRow {
                    ButtonGroup.group: keystoregroup
                    property string keystoretype: 'haveseed'
                    text: qsTranslate('WCKeystoreType', 'I already have a seed')
                }
                M3RadioRow {
                    ButtonGroup.group: keystoregroup
                    property string keystoretype: 'masterkey'
                    text: qsTranslate('WCKeystoreType', 'Use a master key')
                }
                M3RadioRow {
                    enabled: false
                    visible: false
                    ButtonGroup.group: keystoregroup
                    property string keystoretype: 'hardware'
                    text: qsTranslate('WCKeystoreType', 'Use a hardware device')
                }
            }
        }
    }
}
