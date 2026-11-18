import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// "LNURL Payment request" of the Material 3 GUI, opened by PaymentFlow (invoiceParser.onLnurlRetrieved);
// replaces the classic LnurlPayRequestDialog.
// repeats: components/LnurlPayRequestDialog.qml:10-148 @ e6df7e1c8 (contract: invoiceParser; commentValid,
// amountValid between min_sendable_sat and max_sendable_sat, valid; the range notice when min and max differ;
// provider and description; the amount prefilled with the minimum, editable only when min and max differ, every
// change copied to invoiceParser.amountOverride; the message field with its limit, color and counter, shown
// when comments are allowed; Pay... enabled when valid, it asks for the invoice with the message and closes).
// Look: an M3Dialog (M2-MAP F-2): the notice as M3InfoText, provider and description as detail rows, the
// amount as M3AmountField, the message as M3TextArea (over the limit: the error outline). A fixed amount is shown
// read-only in both fields (the classic disables the bitcoin field and keeps it in the normal color).
// Strings carried over keep the translation context of LnurlPayRequestDialog.qml.
M3Dialog {
    id: dialog

    title: qsTranslate('LnurlPayRequestDialog', 'LNURL Payment request')
    iconSource: Qt.resolvedUrl('../../icons/m3/link.png')

    property var invoiceParser  // type: InvoiceParser

    property bool commentValid: comment.text.length <= invoiceParser.lnurlData['comment_allowed']
    property bool amountValid: amountBtc.textAsSats.satsInt >= parseInt(invoiceParser.lnurlData['min_sendable_sat'])
        && amountBtc.textAsSats.satsInt <= parseInt(invoiceParser.lnurlData['max_sendable_sat'])
    property bool valid: commentValid && amountValid

    // the dialog never grows past the free zone (keyboard included): the content scrolls instead
    // (centered: the same margin above and below, clear of the status bar and of the navigation bar; while the
    // keyboard is open the navigation bar is under it and the margin is smaller, the height is short then;
    // as PasswordDialog.qml)
    height: Math.min(implicitHeight, parent
        ? parent.height - 2 * (app.keyboardFreeZone.state != 'visible'
            ? m3.space24 + Math.max(app.statusBarHeight, app.navigationBarHeight)
            : m3.space8 + app.statusBarHeight)
        : implicitHeight)
    onClosed: destroy()

    contentItem: Flickable {
        id: flick
        implicitHeight: form.implicitHeight
        contentHeight: form.implicitHeight
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: form
            width: flick.width
            spacing: m3.space12

            M3InfoText {
                Layout.fillWidth: true
                compact: true
                visible: invoiceParser.lnurlData['min_sendable_sat'] != invoiceParser.lnurlData['max_sendable_sat']
                text: qsTranslate('LnurlPayRequestDialog', 'Amount must be between %1 and %2 %3').arg(Config.formatSats(invoiceParser.lnurlData['min_sendable_sat'])).arg(Config.formatSats(invoiceParser.lnurlData['max_sendable_sat'])).arg(Config.baseUnit)
            }

            M3ListGroup {
                Layout.fillWidth: true
                color: m3.surfaceContainer

                M3DetailRow {
                    label: qsTranslate('LnurlPayRequestDialog', 'Provider')
                    text: invoiceParser.lnurlData['domain']
                }
                M3DetailRow {
                    label: qsTranslate('LnurlPayRequestDialog', 'Description')
                    text: invoiceParser.lnurlData['metadata_plaintext']
                }
            }

            // the label 'Amount' of the classic form is the label of the field
            M3AmountField {
                id: amountBtc
                Layout.fillWidth: true
                text: Config.formatSatsForEditing(invoiceParser.lnurlData['min_sendable_sat'])
                readOnly: !(invoiceParser.lnurlData['min_sendable_sat'] != invoiceParser.lnurlData['max_sendable_sat'])
                onTextAsSatsChanged: {
                    invoiceParser.amountOverride = textAsSats
                }
            }

            M3Text {
                visible: invoiceParser.lnurlData['comment_allowed'] > 0
                role: 'labelLarge'
                color: m3.surfaceVariantOn
                text: qsTranslate('LnurlPayRequestDialog', 'Message')
            }
            M3TextArea {
                id: comment
                Layout.fillWidth: true
                Layout.minimumHeight: 160
                visible: invoiceParser.lnurlData['comment_allowed'] > 0
                wrapMode: TextEdit.Wrap
                placeholderText: qsTranslate('LnurlPayRequestDialog', 'Enter an (optional) message for the receiver')
                color: text.length > invoiceParser.lnurlData['comment_allowed'] ? m3.error : m3.surfaceOn
                errorText: text.length > invoiceParser.lnurlData['comment_allowed'] ? ' ' : ''
            }
            M3Text {
                Layout.leftMargin: m3.space16
                visible: invoiceParser.lnurlData['comment_allowed'] > 0
                role: 'bodySmall'
                color: m3.surfaceVariantOn
                text: qsTranslate('LnurlPayRequestDialog', '%1 characters remaining').arg(Math.max(0, (invoiceParser.lnurlData['comment_allowed'] - comment.text.length) ))
            }
        }
    }

    buttons: [
        M3Button {
            variant: 'filled'
            text: qsTranslate('LnurlPayRequestDialog', 'Pay...')
            icon.source: Qt.resolvedUrl('../../icons/m3/check.png')
            enabled: valid
            onClicked: {
                invoiceParser.lnurlGetInvoice(comment.text)
                dialog.close()
            }
        }
    ]
}
