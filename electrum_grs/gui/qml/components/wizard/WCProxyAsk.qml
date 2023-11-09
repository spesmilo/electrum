import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "../controls"

WizardComponent {
    valid: true

    function apply() {
        wizard_data['want_proxy'] = wantproxygroup.checkedButton.wantproxy
    }

    ColumnLayout {
        width: parent.width

        Label {
            Layout.fillWidth: true
            text: qsTr('Do you use a local proxy service such as TOR to reach the internet?')
            wrapMode: Text.Wrap
        }

        ButtonGroup {
            id: wantproxygroup
            onCheckedButtonChanged: checkIsLast()
        }

        ElRadioButton {
            ButtonGroup.group: wantproxygroup
            property bool wantproxy: true
            text: qsTr('Yes')
        }
        ElRadioButton {
            ButtonGroup.group: wantproxygroup
            property bool wantproxy: false
            text: qsTr('No')
            checked: true
        }

    }

}
