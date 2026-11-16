import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "controls"

// History tab: placeholder until the Material 3 history list. The transaction list is on the
// Wallet tab for now.
Item {
    M3Text {
        anchors.centerIn: parent
        width: parent.width - 2 * m3.space24
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.Wrap
        role: 'bodyLarge'
        color: m3.surfaceVariantOn
        text: qsTr('The transaction history is on the Wallet tab for now.')
    }
}
