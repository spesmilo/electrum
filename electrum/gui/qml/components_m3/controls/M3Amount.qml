import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

// Amount in the base unit with its unit, and optionally the fiat value below or beside.
// amount: a QEAmount (as the classic FormattedAmount). Fiat follows the same rules as the classic
// controls/FormattedAmount.qml: historic rate when `historic` and `timestamp`, else a recent rate.
GridLayout {
    id: root

    required property var amount
    property string role: 'bodyLarge'
    property string unitRole: role
    property color color: m3.surfaceOn
    property color unitColor: m3.surfaceVariantOn
    property bool showFiat: true
    property bool fiatBelow: true
    property string fiatRole: 'bodyMedium'
    property bool historic: Daemon.fx.historicRates
    property int timestamp: 0

    columns: fiatBelow ? 1 : 2
    columnSpacing: m3.space8
    rowSpacing: 0

    RowLayout {
        spacing: m3.space4
        M3Text {
            role: root.role
            color: root.color
            text: root.amount.msatsInt != 0 ? Config.formatMilliSats(root.amount) : Config.formatSats(root.amount)
        }
        M3Text {
            role: root.unitRole
            color: root.unitColor
            text: Config.baseUnit
        }
    }

    M3Text {
        id: fiatLabel
        visible: root.showFiat && Daemon.fx.enabled && text !== ''
        role: root.fiatRole
        color: m3.surfaceVariantOn
    }

    function _setFiatValue() {
        if (!root.showFiat)
            return
        if (root.historic && root.timestamp)
            fiatLabel.text = Daemon.fx.fiatValueHistoric(root.amount, root.timestamp) + ' ' + Daemon.fx.fiatCurrency
        else
            fiatLabel.text = Daemon.fx.isRecent(root.timestamp)
                ? Daemon.fx.fiatValue(root.amount) + ' ' + Daemon.fx.fiatCurrency
                : ''
    }

    onAmountChanged: _setFiatValue()

    Connections {
        target: Daemon.fx
        function onQuotesUpdated() { root._setFiatValue() }
    }

    Connections {
        target: root.amount
        function onValueChanged() { root._setFiatValue() }
    }

    Component.onCompleted: _setFiatValue()
}
