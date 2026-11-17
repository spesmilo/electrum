import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

// One row of the wallet history (Wallet tab "Recent" and the History tab), a delegate of a view over
// Daemon.currentWallet.historyModel: reads the roles of qetransactionlistmodel.py through the context
// property `model`, as the classic delegate does.
// repeats: components/controls/HistoryItemDelegate.qml:45-49 (details), :60-82 (state of the tx),
// :86-133 (label, amount, date, fiat), :149-160 (refresh on unit / fx changes) @ 4f36c4489.
// Fixed height (one line of label, one line of state) so that a non-interactive view of N rows has a
// known height. The value has the sign: '+' added before an incoming amount (the core formats an
// outgoing one with '-').
M3ListItem {
    id: root

    // the roles used below; `model` comes from the view (ListView/Repeater delegate context)
    readonly property bool txLightning: model.lightning
    readonly property string txLabel: model.label
    readonly property var txValue: model.value
    readonly property string txDate: model.date ? model.date : ''
    readonly property int txTimestamp: model.timestamp ? model.timestamp : 0
    readonly property int txConfirmations: model.confirmations ? model.confirmations : 0
    // read only for on-chain rows: lightning rows have no 'complete' role (the model logs a missing key)
    readonly property string txSection: !model.lightning && model.section ? model.section : ''
    readonly property bool txComplete: !model.lightning && model.complete === true
    readonly property string txKey: model.key

    readonly property bool _incoming: txValue && txValue.satsInt >= 0
    // as the classic icon choice: complete and not local -> confirmations (0 = unconfirmed), else 'local'
    readonly property bool _local: !txLightning && !(txComplete && txSection != 'local')
    readonly property bool _unconfirmed: !txLightning && !_local && txConfirmations == 0
    readonly property bool _fewConfirmations: !txLightning && !_local && txConfirmations > 0 && txConfirmations < 6

    property string _valueText
    property string _fiatText

    implicitHeight: 72
    height: 72
    supportingMaxLines: 1

    headline: txLabel !== '' ? txLabel : qsTranslate('HistoryItemDelegate', '<no label>')
    // unconfirmed and local rows: the status string of the model alone (it is long, and says on-chain).
    // 1-5 confirmations: the count first, then the date, without "On-chain" (only on-chain rows have
    // confirmations, and the icon says it): a narrow row with a long amount elides the date, not the count.
    supporting: _local || _unconfirmed
        ? txDate
        : _fewConfirmations
            ? qsTr('%1 conf.').arg(txConfirmations) + (txDate !== '' ? ' \u00B7 ' + txDate : '')
            : (txLightning ? qsTranslate('BalanceSummary', 'Lightning') : qsTranslate('BalanceSummary', 'On-chain'))
                + (txDate !== '' ? ' \u00B7 ' + txDate : '')

    leading: Component {
        Rectangle {
            implicitWidth: 40
            implicitHeight: 40
            radius: 20
            color: root._local
                ? m3.errorContainer
                : root._unconfirmed
                    ? m3.surfaceContainerHighest
                    : root.txLightning ? m3.tertiaryContainer : m3.primaryContainer
            M3Icon {
                anchors.centerIn: parent
                size: 24
                source: Qt.resolvedUrl(root._local
                    ? '../../../icons/m3/warning.png'
                    : root._unconfirmed
                        ? '../../../icons/m3/sync.png'
                        : root.txLightning ? '../../../icons/m3/bolt.png' : '../../../icons/m3/link.png')
                color: root._local
                    ? m3.errorContainerOn
                    : root._unconfirmed
                        ? m3.surfaceVariantOn
                        : root.txLightning ? m3.tertiaryContainerOn : m3.primaryContainerOn
            }
        }
    }

    trailing: Component {
        ColumnLayout {
            spacing: 0
            M3Text {
                Layout.alignment: Qt.AlignRight
                role: 'titleMedium'
                color: root._incoming ? m3.success : m3.surfaceOn
                text: root._valueText
            }
            M3Text {
                Layout.alignment: Qt.AlignRight
                visible: text !== ''
                role: 'bodySmall'
                color: m3.surfaceVariantOn
                text: root._fiatText
            }
        }
    }

    function updateValueText() {
        if (!root.txValue) {
            root._valueText = ''
            return
        }
        var s = Config.formatSats(root.txValue)
        root._valueText = root.txValue.satsInt > 0 ? '+' + s : s
    }

    // as the classic fiat label: historic rate when enabled and known, else a recent rate, else nothing
    function updateFiatText() {
        if (!Daemon.fx.enabled || !root.txValue) {
            root._fiatText = ''
        } else if (Daemon.fx.historicRates && root.txTimestamp) {
            root._fiatText = Daemon.fx.fiatValueHistoric(root.txValue, root.txTimestamp) + ' ' + Daemon.fx.fiatCurrency
        } else if (Daemon.fx.isRecent(root.txTimestamp)) {
            root._fiatText = Daemon.fx.fiatValue(root.txValue, false) + ' ' + Daemon.fx.fiatCurrency
        } else {
            root._fiatText = ''
        }
    }

    onTxValueChanged: { updateValueText(); updateFiatText() }
    onTxTimestampChanged: updateFiatText()

    onClicked: {
        if (root.txLightning)
            app.pushPage(app.routes.lightningPaymentDetails, {'key': root.txKey})
        else
            app.pushPage(app.routes.txDetails, {'txid': root.txKey})
    }

    // the model items are not QObjects: refresh the formatted strings on the events that change them
    Connections {
        target: Config
        function onBaseUnitChanged() { root.updateValueText() }
        function onThousandsSeparatorChanged() { root.updateValueText() }
    }

    Connections {
        target: Daemon.fx
        function onHistoricRatesChanged() { root.updateFiatText() }
        function onQuotesUpdated() { root.updateFiatText() }
        function onHistoryUpdated() { root.updateFiatText() }
        function onEnabledUpdated() { root.updateFiatText() }
    }

    Component.onCompleted: { updateValueText(); updateFiatText() }
}
