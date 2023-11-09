import QtQuick
import QtQuick.Controls

import org.electrum 1.0

TextField {
    id: amount

    required property TextField fiatfield

    font.family: FixedFont
    placeholderText: qsTr('Amount')
    inputMethodHints: Qt.ImhDigitsOnly
    validator: RegularExpressionValidator {
        regularExpression: Config.btcAmountRegex
    }

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
