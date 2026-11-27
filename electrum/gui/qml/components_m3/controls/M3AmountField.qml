import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

// Amount input of the Material 3 GUI: the pair of the classic BtcField and FiatField in one control, two
// outlined fields with the unit after each (the fiat row only while Daemon.fx is enabled, `fiatVisible`).
// repeats: components/controls/BtcField.qml:6-37 and FiatField.qml:6-34 (fixed font, digits
// input, the amount regexes, textAsSats, the conversion to fiat while the bitcoin field is edited and back while
// the fiat field is edited, the re-format on a base unit change, the fiat update on new quotes).
// API as the classic pair, so screens move their logic over verbatim: `text` (the bitcoin field, in the base
// unit), `textAsSats`, `msatPrecision`, `readOnly` (both fields; read-only text in m3.primary, as the classic
// screens color it), `btcfield` / `fiatfield` (the two TextFields, e.g. for `font` or focus).
// Added: `fiatText`, `fiatVisible`, `fieldMaximumWidth` (320 by default), `trailing` (items after the unit of the
// bitcoin row, e.g. the "Max" switch).
// Moving a classic BtcField + FiatField pair here: `font: amountBtc.font` (FontMetrics) -> `amountBtc.btcfield.font`;
// `Layout.preferredWidth` of each field -> `fieldMaximumWidth` (both fields fill their row up to it; paddings:
// `btcfield.leftPadding`...); `visible: Daemon.fx.enabled` of the fiat field -> `fiatVisible` (the default);
// `color` and the `fiatfield:` / `btcfield:` cross-links -> drop (the control colors and links the pair itself).
ColumnLayout {
    id: root

    property alias text: amount.text
    property alias textAsSats: amount.textAsSats
    property alias msatPrecision: amount.msatPrecision
    property alias fiatText: amountFiat.text
    property alias btcfield: amount
    property alias fiatfield: amountFiat
    property bool readOnly: false
    property bool fiatVisible: Daemon.fx.enabled
    property real fieldMaximumWidth: 320
    property list<Item> trailing

    spacing: m3.space8

    RowLayout {
        Layout.fillWidth: true
        spacing: m3.space8

        TextField {
            id: amount

            property bool msatPrecision: false

            Layout.fillWidth: true
            Layout.maximumWidth: root.fieldMaximumWidth
            Material.containerStyle: Material.Outlined
            font.pixelSize: m3.textStyle('bodyLarge').size
            readOnly: root.readOnly
            color: readOnly ? m3.primary : m3.surfaceOn

            font.family: FixedFont
            placeholderText: qsTranslate('BtcField', 'Amount')
            inputMethodHints: Qt.ImhDigitsOnly
            validator: RegularExpressionValidator {
                regularExpression: amount.msatPrecision ? Config.btcAmountRegexMsat : Config.btcAmountRegex
            }

            property var textAsSats
            onTextChanged: {
                textAsSats = Config.unitsToSats(amount.text)
                if (amountFiat.activeFocus)
                    return
                amountFiat.text = text == '' ? '' : Daemon.fx.fiatValue(amount.textAsSats)
            }

            Connections {
                target: Config
                function onBaseUnitChanged() {
                    amount.text = amount.textAsSats.satsInt != 0
                        ? Config.satsToUnits(amount.textAsSats)
                        : ''
                }
            }

            Component.onCompleted: amount.textChanged()
        }
        M3Text {
            role: 'bodyLarge'
            color: m3.surfaceVariantOn
            text: Config.baseUnit
        }
        // as the classic rows: the trailing items follow the unit; without a visible one this (empty) row fills
        // the rest itself, as a spacer would, so a hidden "Max" costs no extra spacing. The row stays visible:
        // an invisible parent hides its children, so `visible: implicitWidth > 0` would never come back.
        Row {
            id: trailingRow
            Layout.fillWidth: implicitWidth <= 0
            Layout.alignment: Qt.AlignVCenter
            spacing: m3.space8
            children: root.trailing
        }
    }

    RowLayout {
        Layout.fillWidth: true
        visible: root.fiatVisible
        spacing: m3.space8

        TextField {
            id: amountFiat

            Layout.fillWidth: true
            Layout.maximumWidth: root.fieldMaximumWidth
            Material.containerStyle: Material.Outlined
            font.pixelSize: m3.textStyle('bodyLarge').size
            readOnly: root.readOnly
            color: readOnly ? m3.primary : m3.surfaceOn

            font.family: FixedFont
            placeholderText: qsTranslate('FiatField', 'Amount')
            inputMethodHints: Qt.ImhDigitsOnly
            validator: RegularExpressionValidator {
                regularExpression: Daemon.fx.fiatAmountRegex
            }

            onTextChanged: {
                if (amountFiat.activeFocus)
                    amount.text = text == ''
                        ? ''
                        : Config.satsToUnits(Daemon.fx.satoshiValue(amountFiat.text))
            }

            Connections {
                target: Daemon.fx
                function onQuotesUpdated() {
                    amountFiat.text = amount.text == ''
                        ? ''
                        : Daemon.fx.fiatValue(Config.unitsToSats(amount.text))
                }
            }
        }
        M3Text {
            Layout.fillWidth: true
            role: 'bodyLarge'
            color: m3.surfaceVariantOn
            text: Daemon.fx.fiatCurrency
        }
    }
}
