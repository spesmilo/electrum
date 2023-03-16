import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1
import QtQuick.Controls.Material 2.0

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

        RadioButton {
            ButtonGroup.group: wantproxygroup
            property bool wantproxy: true
            text: qsTr('Yes')
        }
        RadioButton {
            ButtonGroup.group: wantproxygroup
            property bool wantproxy: false
            text: qsTr('No')
            checked: true
        }

    }

}
