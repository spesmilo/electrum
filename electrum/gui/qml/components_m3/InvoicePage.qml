import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "../components/controls" as CC
import "controls"

// "Pay invoice" of the Material 3 GUI (replaces the classic InvoiceDialog, see PaymentFlow).
// repeats: components/InvoiceDialog.qml:13-27, 56-71, 75-461, 465-545 @ 4f36c4489 (contract, status, address,
// description, amount and its editing with Max and fiat, technical properties, Save / Pay..., onCompleted,
// broadcast success, fiat updates). Only the look differs; the logic and its conditions are those of the classic.
// Contract = the contract of InvoiceDialog used by PaymentFlow and Invoices.qml: invoice, payImmediately,
// broadcastTxid, doPay, invoiceAmountChanged, close() (takes this page off the stack, only when it is on top);
// plus `flow` (PaymentFlow, set on creation: the page is loaded by URL, PaymentFlow.doPay() pays).
// Strings carried over from InvoiceDialog.qml keep its translation context (qsTranslate('InvoiceDialog', ...)).
M3Page {
    id: root

    readonly property bool m3InvoicePage: true

    property QtObject flow  // PaymentFlow, set on creation
    property var invoice  // type Invoice
    property bool payImmediately: false
    property string broadcastTxid

    signal doPay
    signal invoiceAmountChanged

    // the handlers of the classic InvoiceDialog factory (WalletMainView.qml:508-536, 540-545 @ 4f36c4489);
    // the payment itself is PaymentFlow.doPay(), shared with the classic InvoiceDialog
    onDoPay: flow.doPay(root, invoice)

    Connections {
        target: Daemon.currentWallet
        function onSaveTxSuccess(txid) {
            root.close()
        }
    }

    title: invoice.invoiceType == Invoice.OnchainInvoice
        ? qsTranslate('InvoiceDialog', 'On-chain Invoice')
        : qsTranslate('InvoiceDialog', 'Lightning Invoice')

    property bool _canMax: invoice.invoiceType == Invoice.OnchainInvoice

    property var _invoice_amount: invoice.amount  // type: Amount

    readonly property bool _isLightning: invoice.invoiceType == Invoice.LightningInvoice
    readonly property bool _inProgress: invoice.status == Invoice.Inflight
        || invoice.status == Invoice.Routing
        || invoice.status == Invoice.Unconfirmed
    readonly property bool _paid: invoice.status == Invoice.Paid
    // the amount is shown as a figure only when it is a real amount (InvoiceDialog.qml:166-214)
    readonly property bool _amountValid: !_invoice_amount.isMax && !_invoice_amount.isEmpty
    property bool _editmode: false
    readonly property bool _wide: root.width >= 600
    // LN_EXPIRY_NEVER of invoices.py (100 years)
    readonly property real _lnExpiryNever: 100 * 365 * 24 * 60 * 60

    // takes only this page off the stack, and only when it is on top (finding 2)
    function close() {
        if (app.stack.currentItem === root)
            app.stack.pop()
        else
            console.log('M3: InvoicePage.close(): the page is not on top, left on the stack')
    }

    // A payment started from this page may still report to it: a dialog is open over the page (confirmation,
    // "Pay on-chain instead?", authentication), its transaction is being broadcast, or a Lightning payment is
    // in flight. PaymentFlow then does not replace this page by a link to another invoice (it pushes the new
    // page and sets `superseded`).
    function paymentUnderway() {
        return app.activeDialogs.length > 0 || broadcastTxid !== '' || _inProgress
    }

    // set by PaymentFlow when a page for another invoice of the same invoice object was pushed over this one:
    // the object no longer holds what this page was opened for, so the page shows nothing and leaves the stack
    // when the user comes back to it
    property bool superseded: false
    StackView.onActivated: {
        if (superseded)
            Qt.callLater(root.close)
    }

    function share(title, text) {
        var dialog = app.genericShareDialog.createObject(app, { title: title, text: text })
        dialog.open()
    }

    // InvoiceDialog.qml:475-479 and 493-497
    function _takeEnteredAmount() {
        if (invoice.amount.isEmpty) {
            invoice.amountOverride = Config.unitsToSats(amountBtc.text)
            if (amountMax.checked)
                invoice.amountOverride.isMax = true
        }
    }

    function setFiatValue() {
        fiatValue.value = Daemon.fx.fiatValue(invoice.amount, false)
    }

    // status card: colors and icon by the status, as the icon styles of InvoiceDialog.qml:57-71
    readonly property string _statusStyle: invoice.status == Invoice.Failed || invoice.status == Invoice.Unknown
        ? 'warn'
        : invoice.status == Invoice.Expired
            ? 'error'
            : _inProgress
                ? 'progress'
                : _paid
                    ? 'done'
                    : invoice.status == Invoice.Unpaid && invoice.expiration > 0
                        ? invoice.canPay
                            ? 'pending'
                            : invoice.userinfoStatus == Invoice.Warning
                                ? 'warn'
                                : 'error'
                        : 'info'

    ColumnLayout {
        anchors.fill: parent
        spacing: 0
        visible: !root.superseded

        Flickable {
            id: flickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentHeight: content.implicitHeight + 2 * m3.space16
            interactive: height < contentHeight
            boundsBehavior: Flickable.StopAtBounds

            ColumnLayout {
                id: content
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
                spacing: m3.space16

                // --- hero: kind, amount, fiat, description ---
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: m3.space8

                    Rectangle {
                        Layout.alignment: Qt.AlignHCenter
                        implicitWidth: 56
                        implicitHeight: 56
                        radius: 28
                        color: root._isLightning ? m3.tertiaryContainer : m3.primaryContainer
                        M3Icon {
                            anchors.centerIn: parent
                            source: root._isLightning
                                ? Qt.resolvedUrl('../../icons/m3/bolt.png')
                                : Qt.resolvedUrl('../../icons/m3/north_east.png')
                            color: root._isLightning ? m3.tertiaryContainerOn : m3.primaryContainerOn
                        }
                    }

                    M3Text {
                        Layout.fillWidth: true
                        horizontalAlignment: Text.AlignHCenter
                        role: 'labelLarge'
                        color: m3.surfaceVariantOn
                        text: qsTranslate('InvoiceDialog', 'Amount to send')
                    }

                    // amount as text (not editing)
                    ColumnLayout {
                        Layout.fillWidth: true
                        visible: !root._editmode
                        spacing: 0

                        M3Text {
                            Layout.fillWidth: true
                            visible: root._invoice_amount.isMax
                            horizontalAlignment: Text.AlignHCenter
                            wrapMode: Text.Wrap
                            role: 'headlineSmall'
                            text: qsTranslate('InvoiceDialog', 'All on-chain funds')
                        }
                        M3Text {
                            Layout.fillWidth: true
                            visible: root._invoice_amount.isEmpty
                            horizontalAlignment: Text.AlignHCenter
                            role: 'headlineSmall'
                            color: m3.surfaceVariantOn
                            text: qsTranslate('InvoiceDialog', 'not specified')
                        }
                        Item {
                            Layout.fillWidth: true
                            implicitHeight: amountRow.implicitHeight
                            visible: root._amountValid

                            Row {
                                id: amountRow
                                anchors.horizontalCenter: parent.horizontalCenter
                                spacing: m3.space8

                                readonly property string amountText: root._isLightning
                                    ? Config.formatMilliSats(root.invoice.amount, false)
                                    : Config.formatSats(root.invoice.amount, false)
                                readonly property int heroSize: m3.textStyle('amountHero').size

                                // long amounts get a smaller font, down to titleLarge, so that the row fits
                                // (TextMetrics is not an Item: it has no parent, the row is named by id)
                                TextMetrics {
                                    id: amountMetrics
                                    font.family: FixedFont
                                    font.weight: m3.textStyle('amountHero').weight
                                    font.pixelSize: amountRow.heroSize
                                    text: amountRow.amountText
                                }

                                M3Text {
                                    anchors.baseline: unitLabel.baseline
                                    role: 'amountHero'
                                    font.family: FixedFont
                                    font.pixelSize: Math.max(m3.textStyle('titleLarge').size,
                                        Math.min(amountRow.heroSize, Math.floor(amountRow.heroSize
                                            * (content.width - unitLabel.implicitWidth - amountRow.spacing)
                                            / Math.max(1, amountMetrics.advanceWidth))))
                                    text: amountRow.amountText
                                }
                                M3Text {
                                    id: unitLabel
                                    role: 'titleLarge'
                                    color: m3.surfaceVariantOn
                                    text: Config.baseUnit
                                }
                            }
                        }
                        M3Text {
                            id: fiatValue
                            Layout.fillWidth: true
                            visible: Daemon.fx.enabled && root._amountValid
                            horizontalAlignment: Text.AlignHCenter
                            role: 'bodyLarge'
                            color: m3.surfaceVariantOn
                            property string value
                            text: value + ' ' + Daemon.fx.fiatCurrency
                        }
                    }

                    // amount editing (InvoiceDialog.qml:218-308)
                    ColumnLayout {
                        id: amountEditor
                        Layout.fillWidth: true
                        visible: root._editmode
                        enabled: !(invoice.status == Invoice.Expired && root._invoice_amount.isEmpty)
                        spacing: m3.space8

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: m3.space8

                            CC.BtcField {
                                id: amountBtc
                                Layout.fillWidth: true
                                Layout.maximumWidth: 320
                                Material.containerStyle: Material.Outlined
                                font.pixelSize: m3.textStyle('bodyLarge').size
                                fiatfield: amountFiat
                                readOnly: amountMax.checked
                                msatPrecision: root._isLightning
                                color: readOnly ? m3.primary : m3.surfaceOn
                                onTextAsSatsChanged: {
                                    if (!amountMax.checked)
                                        invoice.amountOverride.copyFrom(textAsSats)
                                }
                                Connections {
                                    target: invoice.amountOverride
                                    function onSatsIntChanged() {
                                        console.log('amountOverride satsIntChanged, sats=' + invoice.amountOverride.satsInt)
                                        if (amountMax.checked)  // amountOverride updated by max amount estimate
                                            amountBtc.text = Config.formatSatsForEditing(invoice.amountOverride.satsInt)
                                    }
                                }
                            }
                            M3Text {
                                role: 'bodyLarge'
                                color: m3.surfaceVariantOn
                                text: Config.baseUnit
                            }
                            Item { Layout.fillWidth: true; visible: !amountMax.visible }
                            Switch {
                                id: amountMax
                                text: qsTranslate('InvoiceDialog', 'Max')
                                visible: root._canMax
                                checked: false
                                // the classic reacts to user changes only (activeFocus); onToggled is that
                                onToggled: {
                                    invoice.amountOverride.isMax = checked
                                    if (checked) {
                                        maxAmountMessage.text = ''
                                        invoice.updateMaxAmount()
                                    }
                                }
                            }
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            visible: Daemon.fx.enabled
                            spacing: m3.space8

                            CC.FiatField {
                                id: amountFiat
                                Layout.fillWidth: true
                                Layout.maximumWidth: 320
                                Material.containerStyle: Material.Outlined
                                font.pixelSize: m3.textStyle('bodyLarge').size
                                btcfield: amountBtc
                                readOnly: amountMax.checked
                                color: readOnly ? m3.primary : m3.surfaceOn
                            }
                            M3Text {
                                Layout.fillWidth: true
                                role: 'bodyLarge'
                                color: m3.surfaceVariantOn
                                text: Daemon.fx.fiatCurrency
                            }
                        }

                        M3Card {
                            id: maxAmountCard
                            Layout.fillWidth: true
                            visible: amountMax.checked && maxAmountMessage.text
                            color: m3.surfaceContainer
                            padding: m3.space12
                            M3Text {
                                id: maxAmountMessage
                                width: parent.width
                                role: 'bodyMedium'
                                color: m3.surfaceVariantOn
                                wrapMode: Text.Wrap
                                lineHeightMode: Text.ProportionalHeight
                                lineHeight: 1.0

                                Connections {
                                    target: invoice
                                    function onMaxAmountMessage(message) {
                                        maxAmountMessage.text = message
                                    }
                                }
                            }
                        }
                    }

                    // description of the invoice
                    Rectangle {
                        Layout.alignment: Qt.AlignHCenter
                        Layout.maximumWidth: content.width
                        Layout.topMargin: m3.space4
                        visible: invoice.message
                        implicitWidth: Math.min(content.width, descriptionText.implicitWidth + 2 * m3.space12)
                        implicitHeight: descriptionText.implicitHeight + 2 * m3.space8
                        radius: m3.radiusS
                        color: m3.surfaceContainer
                        M3Text {
                            id: descriptionText
                            anchors.fill: parent
                            anchors.leftMargin: m3.space12
                            anchors.rightMargin: m3.space12
                            horizontalAlignment: Text.AlignHCenter
                            role: 'bodyLarge'
                            wrapMode: Text.Wrap
                            lineHeightMode: Text.ProportionalHeight
                            lineHeight: 1.0
                            text: invoice.message
                        }
                    }
                }

                // --- status (InvoiceDialog.qml:50-73) ---
                M3Card {
                    id: statusCard
                    Layout.fillWidth: true
                    visible: statusText.text
                    padding: m3.space12
                    color: root._statusStyle === 'done'
                        ? m3.successContainer
                        : root._statusStyle === 'error'
                            ? m3.errorContainer
                            : root._statusStyle === 'warn'
                                ? m3.tertiaryContainer
                                : m3.secondaryContainer
                    readonly property color onColor: root._statusStyle === 'done'
                        ? m3.successContainerOn
                        : root._statusStyle === 'error'
                            ? m3.errorContainerOn
                            : root._statusStyle === 'warn'
                                ? m3.tertiaryContainerOn
                                : m3.secondaryContainerOn

                    RowLayout {
                        width: parent.width
                        spacing: m3.space12
                        BusyIndicator {
                            Layout.preferredWidth: 24
                            Layout.preferredHeight: 24
                            Layout.alignment: Qt.AlignTop
                            visible: root._statusStyle === 'progress'
                            running: visible
                        }
                        M3Icon {
                            Layout.alignment: Qt.AlignTop
                            visible: root._statusStyle !== 'progress'
                            color: statusCard.onColor
                            source: root._statusStyle === 'done'
                                ? Qt.resolvedUrl('../../icons/m3/check_circle.png')
                                : root._statusStyle === 'error'
                                    ? Qt.resolvedUrl('../../icons/m3/error.png')
                                    : root._statusStyle === 'warn'
                                        ? Qt.resolvedUrl('../../icons/m3/warning.png')
                                        : Qt.resolvedUrl('../../icons/m3/info.png')
                        }
                        M3Text {
                            id: statusText
                            Layout.fillWidth: true
                            role: 'bodyMedium'
                            color: statusCard.onColor
                            wrapMode: Text.Wrap
                            lineHeightMode: Text.ProportionalHeight
                            lineHeight: 1.0
                            text: invoice.userinfo ? invoice.userinfo : invoice.statusString
                        }
                    }
                }

                // --- details ---
                M3ListGroup {
                    Layout.fillWidth: true

                    M3ListItem {
                        visible: invoice.invoiceType == Invoice.OnchainInvoice
                        headline: qsTranslate('InvoiceDialog', 'Address')
                        supporting: invoice.address
                        supportingMaxLines: 3
                        onClicked: root.share(qsTranslate('InvoiceDialog', 'Address'), invoice.address)
                        trailing: shareIcon
                    }
                    InfoItem {
                        // N-3: the absolute time of expiry, it needs no recounting; an invoice that never
                        // expires (0, or LN_EXPIRY_NEVER as the core treats it, invoices.py:91,143) has no row
                        visible: invoice.expiration > 0 && invoice.expiration != root._lnExpiryNever && invoice.time > 0
                        headline: invoice.status == Invoice.Expired ? qsTr('Expired') : qsTr('Expires')
                        supporting: invoice.time > 0
                            ? new Date((invoice.time + invoice.expiration) * 1000).toLocaleString(Qt.locale(), Locale.ShortFormat)
                            : ''
                    }
                    InfoItem {
                        visible: root._isLightning && Daemon.currentWallet.isLightning
                        headline: qsTranslate('BalanceDetails', 'Can send')
                        // formatted as the classic FormattedAmount (BalanceDetails.qml:194-197)
                        supporting: (Daemon.currentWallet.lightningCanSend.msatsInt != 0
                                ? Config.formatMilliSats(Daemon.currentWallet.lightningCanSend)
                                : Config.formatSats(Daemon.currentWallet.lightningCanSend))
                            + ' ' + Config.baseUnit
                    }
                    M3ListItem {
                        id: techToggle
                        property bool expanded: false
                        visible: root._isLightning
                        headline: qsTranslate('InvoiceDialog', 'Technical properties')
                        onClicked: expanded = !expanded
                        trailing: Component {
                            M3Icon {
                                source: Qt.resolvedUrl('../../icons/m3/expand_more.png')
                                rotation: techToggle.expanded ? 180 : 0
                            }
                        }
                    }
                }

                // technical properties of a Lightning invoice (InvoiceDialog.qml:313-461)
                M3ListGroup {
                    Layout.fillWidth: true
                    visible: root._isLightning && techToggle.expanded

                    M3ListItem {
                        headline: qsTranslate('InvoiceDialog', 'Recipient Pubkey')
                        supporting: 'pubkey' in invoice.lnprops ? invoice.lnprops.pubkey : ''
                        supportingMaxLines: 4
                        enabled: supporting
                        onClicked: root.share(qsTranslate('InvoiceDialog', 'Node public key'), invoice.lnprops.pubkey)
                        trailing: shareIcon
                    }
                    M3ListItem {
                        headline: qsTranslate('InvoiceDialog', 'Payment hash')
                        supporting: 'payment_hash' in invoice.lnprops ? invoice.lnprops.payment_hash : ''
                        supportingMaxLines: 4
                        enabled: supporting
                        onClicked: root.share(qsTranslate('InvoiceDialog', 'Payment hash'), invoice.lnprops.payment_hash)
                        trailing: shareIcon
                    }
                    InfoItem {
                        visible: 'r' in invoice.lnprops && invoice.lnprops.r.length
                        headline: qsTranslate('InvoiceDialog', 'Routing hints')
                        supportingMaxLines: 12
                        supporting: 'r' in invoice.lnprops
                            ? invoice.lnprops.r.map(function(hint) { return hint.scid + '  ' + hint.node }).join('\n')
                            : ''
                    }
                    M3ListItem {
                        visible: invoice.address
                        headline: qsTranslate('InvoiceDialog', 'Fallback address')
                        supporting: invoice.address
                        supportingMaxLines: 3
                        onClicked: root.share(qsTranslate('InvoiceDialog', 'Address'), invoice.address)
                        trailing: shareIcon
                    }
                }
            }
        }

        // --- actions: below the content, above the keyboard (the page shrinks with the keyboard) ---
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: actions.implicitHeight + 2 * m3.space16
            color: m3.surface

            GridLayout {
                id: actions
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
                columns: root._wide ? 4 : 2
                rowSpacing: m3.space8
                columnSpacing: m3.space8

                M3Button {
                    id: payButton
                    Layout.row: 0
                    Layout.column: root._wide ? 3 : 0
                    Layout.columnSpan: root._wide ? 1 : 2
                    Layout.fillWidth: !root._wide
                    variant: 'filled'
                    size: 56
                    text: root._paid ? qsTr('Done') : qsTranslate('InvoiceDialog', 'Pay...')
                    enabled: root._paid || (invoice.invoiceType != Invoice.Invalid && invoice.canPay)
                    onClicked: {
                        if (root._paid) {
                            root.close()
                            return
                        }
                        root._takeEnteredAmount()
                        root.doPay() // only signal here
                    }
                }
                M3Button {
                    Layout.row: root._wide ? 0 : 1
                    Layout.column: 0
                    Layout.fillWidth: !root._wide
                    Layout.preferredWidth: root._wide ? implicitWidth : 1
                    variant: 'text'
                    text: qsTranslate('InvoiceDialog', 'Save')
                    enabled: !invoice.isSaved && invoice.canSave
                    onClicked: {
                        root._takeEnteredAmount()
                        if (invoice.saveInvoice()) {
                            // finding 2: the invoice list takes the place of this page
                            app.stack.replace(root, Qt.resolvedUrl('../components/Invoices.qml'))
                        }
                    }
                }
                M3Button {
                    Layout.row: root._wide ? 0 : 1
                    Layout.column: 1
                    Layout.fillWidth: !root._wide
                    Layout.preferredWidth: root._wide ? implicitWidth : 1
                    variant: 'text'
                    // a payment in progress goes on when the page is left
                    text: root._inProgress ? qsTr('Hide') : qsTranslate('ScanDialog', 'Cancel')
                    onClicked: root.close()
                }
                Item {
                    Layout.row: 0
                    Layout.column: 2
                    Layout.fillWidth: true
                    visible: root._wide
                }
            }
        }
    }

    Component {
        id: shareIcon
        M3Icon {
            source: Qt.resolvedUrl('../../icons/m3/content_copy.png')
        }
    }

    // a row without an action: no pressed or hover state, no keyboard focus (it promises no tap)
    component InfoItem: M3ListItem {
        hoverEnabled: false
        down: false
        focusPolicy: Qt.NoFocus
    }

    Component.onCompleted: {
        if (invoice.amount.isEmpty && invoice.status != Invoice.Expired) {
            root._editmode = true
        } else if (invoice.amount.isMax) {
            amountMax.checked = true
        }
        setFiatValue()
        if (payImmediately) {
            if (invoice.canPay) {
                doPay()
            }
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onBroadcastSucceeded(txid) {
            if (root.broadcastTxid == txid) {
                // our txid was broadcast successfully, close the page and show success popup
                root.close()
                var successdialog = app.messageDialog.createObject(app, {
                    text: qsTranslate('InvoiceDialog', 'Payment sent.')
                })
                successdialog.open()
            }
        }
    }

    Connections {
        target: Daemon.fx
        function onQuotesUpdated() { root.setFiatValue() }
    }
}
