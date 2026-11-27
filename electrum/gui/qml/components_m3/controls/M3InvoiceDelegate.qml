import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

// One row of the saved invoices (InvoicesPage) or of the payment requests (RequestsPage), a delegate of a
// view over Daemon.currentWallet.invoiceModel / requestModel: reads the roles of qeinvoicelistmodel.py
// through the context property `model`, as the classic delegate does.
// repeats: components/controls/InvoiceDelegate.qml:13-17 (highlight of the current item, getKey), :38-57
// (lightning or on-chain, the on-chain fallback), :59-90 (label: message, else the address of a request;
// amount: empty, 'MAX' or the formatted amount with the base unit), :92-131 (status string and status icon by
// the status 0 / 1 / 3 / 7, fiat value), :142-156 (refresh on unit / fx changes).
// Look: a Material 3 list row (72 high): avatar with the kind (bolt / link, a small link badge for the on-chain
// fallback of a lightning invoice), the label and the amount on the first line, the status with its Material
// Symbol and the fiat value on the second; the current (pressed and held) row in m3.secondaryContainer.
ItemDelegate {
    id: root

    width: ListView.view ? ListView.view.width : implicitWidth
    implicitHeight: Math.max(72, layout.implicitHeight + 2 * m3.space8)

    highlighted: ListView.isCurrentItem

    function getKey() {
        return model.key
    }

    // InvoiceDelegate.qml:103-111: unpaid 0, expired 1, paid 3, unconfirmed 7 have an icon, others none
    readonly property int _status: model.status
    readonly property url _statusIcon: _status == 0
        ? Qt.resolvedUrl('../../../icons/m3/schedule.png')
        : _status == 1
            ? Qt.resolvedUrl('../../../icons/m3/error.png')
            : _status == 3
                ? Qt.resolvedUrl('../../../icons/m3/check_circle.png')
                : _status == 7
                    ? Qt.resolvedUrl('../../../icons/m3/sync.png')
                    : ''
    readonly property color _statusColor: _status == 1
        ? m3.error
        : _status == 3
            ? m3.success
            : m3.surfaceVariantOn

    leftPadding: m3.space16
    rightPadding: m3.space16
    topPadding: m3.space8
    bottomPadding: m3.space8

    background: Rectangle {
        color: root.highlighted
            ? m3.secondaryContainer
            : root.down
                ? Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.statePressed)
                : root.hovered || root.visualFocus
                    ? Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.stateHover)
                    : 'transparent'
    }

    contentItem: RowLayout {
        id: layout
        spacing: m3.space16

        // kind of the invoice (InvoiceDelegate.qml:38-57)
        Rectangle {
            Layout.alignment: Qt.AlignVCenter
            implicitWidth: 40
            implicitHeight: 40
            radius: 20
            color: model.is_lightning ? m3.tertiaryContainer : m3.primaryContainer
            M3Icon {
                anchors.centerIn: parent
                size: 24
                source: model.is_lightning
                    ? Qt.resolvedUrl('../../../icons/m3/bolt.png')
                    : Qt.resolvedUrl('../../../icons/m3/link.png')
                color: model.is_lightning ? m3.tertiaryContainerOn : m3.primaryContainerOn
            }
            // the on-chain fallback of a lightning invoice
            Rectangle {
                visible: model.onchain_fallback
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                anchors.rightMargin: -2
                anchors.bottomMargin: -2
                width: 20
                height: 20
                radius: 10
                color: m3.primaryContainer
                border.width: 2
                border.color: m3.surface
                M3Icon {
                    anchors.centerIn: parent
                    size: 12
                    source: Qt.resolvedUrl('../../../icons/m3/link.png')
                    color: m3.primaryContainerOn
                }
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignVCenter
            spacing: 2

            RowLayout {
                Layout.fillWidth: true
                spacing: m3.space8

                // InvoiceDelegate.qml:61-72: up to two lines, the address (no message) in a smaller font
                M3Text {
                    Layout.fillWidth: true
                    role: model.message ? 'bodyLarge' : 'bodyMedium'
                    text: model.message
                        ? model.message
                        : model.type == 'request'
                            ? model.address
                            : ''
                    elide: Text.ElideRight
                    wrapMode: Text.Wrap
                    maximumLineCount: 2
                }

                M3Text {
                    id: amount
                    role: 'titleMedium'
                    font.family: FixedFont
                    text: model.amount.isEmpty
                        ? ''
                        : model.amount.isMax
                            ? 'MAX'
                            : Config.formatSats(model.amount)
                }

                M3Text {
                    visible: text !== ''
                    role: 'bodyMedium'
                    color: m3.surfaceVariantOn
                    text: model.amount.isEmpty || model.amount.isMax ? '' : Config.baseUnit
                }
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: m3.space4

                M3Icon {
                    visible: root._statusIcon != ''
                    size: 16
                    source: root._statusIcon
                    color: root._statusColor
                }
                M3Text {
                    Layout.fillWidth: true
                    role: 'bodyMedium'
                    color: root._status == 1 ? m3.error : m3.surfaceVariantOn
                    elide: Text.ElideRight
                    text: model.status_str
                }
                M3Text {
                    id: fiatValue
                    visible: Daemon.fx.enabled && !model.amount.isMax
                    role: 'bodySmall'
                    font.family: FixedFont
                    color: m3.surfaceVariantOn
                    text: model.amount.isEmpty ? '' : Daemon.fx.fiatValue(model.amount, false)
                }
                M3Text {
                    visible: Daemon.fx.enabled && !model.amount.isMax
                    role: 'bodySmall'
                    color: m3.surfaceVariantOn
                    text: model.amount.isEmpty ? '' : Daemon.fx.fiatCurrency
                }
            }
        }
    }

    Connections {
        target: Config
        function onBaseUnitChanged() {
            amount.text = model.amount.isEmpty ? '' : Config.formatSats(model.amount)
        }
        function onThousandsSeparatorChanged() {
            amount.text = model.amount.isEmpty ? '' : Config.formatSats(model.amount)
        }
    }
    Connections {
        target: Daemon.fx
        function onQuotesUpdated() {
            fiatValue.text = model.amount.isEmpty ? '' : Daemon.fx.fiatValue(model.amount, false)
        }
    }
}
