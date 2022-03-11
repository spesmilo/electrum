import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

WizardComponent {
    valid: wallet_name.text.length > 0

    onAccept: {
        wizard_data['wallet_name'] = wallet_name.text
    }

    GridLayout {
        columns: 1
        Label { text: qsTr('Wallet name') }
        TextField {
            id: wallet_name
        }
    }
}
