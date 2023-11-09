import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Controls.Material

import org.electrum 1.0

GridLayout {
    required property Amount amount
    property bool showAlt: true
    property bool singleLine: true
    property bool valid: true
    property bool historic: Daemon.fx.historicRates
    property int timestamp: 0

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
            if (historic && timestamp)
                fiatLabel.text = '(' + Daemon.fx.fiatValueHistoric(amount, timestamp) + ' ' + Daemon.fx.fiatCurrency + ')'
            else
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
