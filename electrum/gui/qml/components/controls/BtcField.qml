import QtQuick 2.6
import QtQuick.Controls 2.0

import org.electrum 1.0

TextField {
    id: amount

    required property TextField fiatfield

    font.family: FixedFont
    placeholderText: qsTr('Amount')
    inputMethodHints: Qt.ImhPreferNumbers
    property Amount textAsSats
    onTextChanged: {
        textAsSats = Config.unitsToSats(amount.text)
        if (fiatfield.activeFocus)
            return
        fiatfield.text = text == '' ? '' : Daemon.fx.fiatValue(amount.textAsSats)
    }

    Connections {
        target: Config
        function onBaseUnitChanged() {
            amount.text = amount.textAsSats.satsInt != 0
                ? Config.satsToUnits(amount.textAsSats)
                : ''
        }
    }
}
