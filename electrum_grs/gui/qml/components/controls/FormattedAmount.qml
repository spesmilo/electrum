import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

RowLayout {
    required property Amount amount
    property bool showAlt: true
    Label {
        text: amount.msatsInt > 0 ? Config.formatMilliSats(amount) : Config.formatSats(amount)
        font.family: FixedFont
    }
    Label {
        text: Config.baseUnit
        color: Material.accentColor
    }

    Label {
        visible: showAlt && Daemon.fx.enabled
        text: '(' + Daemon.fx.fiatValue(amount) + ' ' + Daemon.fx.fiatCurrency + ')'
    }
}
