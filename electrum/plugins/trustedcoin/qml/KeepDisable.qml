import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import "../../../gui/qml/components/wizard"

WizardComponent {
    valid: keepordisablegroup.checkedButton

    function apply() {
        wizard_data['trustedcoin_keepordisable'] = keepordisablegroup.checkedButton.keepordisable
    }

    ButtonGroup {
        id: keepordisablegroup
        onCheckedButtonChanged: checkIsLast()
    }

    ColumnLayout {
        Label {
            text: qsTr('Restore 2FA wallet')
        }
        RadioButton {
            ButtonGroup.group: keepordisablegroup
            property string keepordisable: 'keep'
            checked: true
            text: qsTr('Keep')
        }
        RadioButton {
            ButtonGroup.group: keepordisablegroup
            property string keepordisable: 'disable'
            text: qsTr('Disable')
        }
    }
}
