import QtQuick
import QtQuick.Controls

import org.electrum 1.0

TextField {
    id: amount

    required property TextField fiatfield
    property bool msatPrecision: false

    font.family: FixedFont
    placeholderText: qsTr('Amount')
    inputMethodHints: Qt.ImhDigitsOnly
    validator: RegularExpressionValidator {
        regularExpression: msatPrecision ? Config.btcAmountRegexMsat : Config.btcAmountRegex
    }

    property var textAsSats
    onTextChanged: {
        textAsSats = Config.baseunitStrToAmount(amount.text)
        if (fiatfield.activeFocus)
            return
        fiatfield.text = text == '' ? '' : Daemon.fx.fiatValue(amount.textAsSats)
    }

    Connections {
        target: Config
        function onBaseUnitChanged() {
            amount.text = amount.textAsSats.msatsInt != 0
                ? Config.amountToBaseunitStr(amount.textAsSats)
                : ''
        }
    }

    Component.onCompleted: amount.textChanged()
}
