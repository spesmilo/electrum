import QtQuick
import QtQuick.Controls

import org.electrum 1.0

TextField {
    id: amountFiat

    required property TextField btcfield

    font.family: FixedFont
    placeholderText: qsTr('Amount')
    inputMethodHints: Qt.ImhDigitsOnly
    validator: RegularExpressionValidator {
        regularExpression: Daemon.fx.fiatAmountRegex
    }

    onTextChanged: {
        if (amountFiat.activeFocus) {
            var amount = Daemon.fx.satoshiValue(amountFiat.text)
            btcfield.text = (text == '' || amount.isEmpty)
                ? ''
                : Config.amountToBaseunitStr(amount)
        }
    }

    Connections {
        target: Daemon.fx
        function onQuotesUpdated() {
            amountFiat.text = btcfield.text == ''
                ? ''
                : Daemon.fx.fiatValue(Config.baseunitStrToAmount(btcfield.text))
        }
    }

}
