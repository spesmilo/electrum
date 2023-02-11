import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

GridLayout {
    required property Amount amount
    property bool showAlt: true
    property bool singleLine: true
    property bool valid: true

    columns: !valid
                ? 1
                : singleLine
                    ? 3
                    : 2

    Item {
        visible: !valid // empty placeholder if not valid
        Layout.preferredWidth: 1
        Layout.preferredHeight: 1
    }
    Label {
        visible: valid
        text: amount.msatsInt != 0 ? Config.formatMilliSats(amount) : Config.formatSats(amount)
        font.family: FixedFont
    }
    Label {
        visible: valid
        text: Config.baseUnit
        color: Material.accentColor
    }

    Label {
        id: fiatLabel
        Layout.columnSpan: singleLine ? 1 : 2
        visible: showAlt && Daemon.fx.enabled && valid
        font.pixelSize: constants.fontSizeSmall
    }

    function setFiatValue() {
        if (showAlt)
            fiatLabel.text = '(' + Daemon.fx.fiatValue(amount) + ' ' + Daemon.fx.fiatCurrency + ')'
    }

    onAmountChanged: setFiatValue()

    Connections {
        target: Daemon.fx
        function onQuotesUpdated() { setFiatValue() }
    }

    Connections {
        target: amount
        function onValueChanged() {
            setFiatValue()
        }
    }

    Component.onCompleted: setFiatValue()
}
