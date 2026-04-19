import QtQuick
import QtQuick.Controls

import org.electrum 1.0

TextField {
    id: root

    required property TextField fiatfield
    property bool msatPrecision: false

    signal valueChanged

    font.family: FixedFont
    placeholderText: qsTr('Amount')
    inputMethodHints: Qt.ImhDigitsOnly
    validator: RegularExpressionValidator {
        regularExpression: msatPrecision ? Config.btcAmountRegexMsat : Config.btcAmountRegex
    }

    property var textAsSats: Amount {
        // propagate on parent
        onValueChanged: root.valueChanged()
    }

    onTextChanged: {
        textAsSats.copyFrom(Config.baseunitStrToAmount(root.text))
        if (fiatfield.activeFocus)
            return
        fiatfield.text = text == '' ? '' : Daemon.fx.fiatValue(root.textAsSats)
    }

    Connections {
        target: Config
        function onBaseUnitChanged() {
            root.text = !root.textAsSats.isEmpty
                ? Config.amountToBaseunitStr(root.textAsSats)
                : ''
        }
    }

    Component.onCompleted: root.textChanged()
}
