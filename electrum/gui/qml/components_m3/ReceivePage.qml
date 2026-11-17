import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// "Receive Payment" of the Material 3 GUI: one payment request, a page on the stack (M2-MAP F-1), opened by
// PaymentFlow.openRequest(key) after a request was created or from the request list; replaces the classic
// ReceiveDialog.
// repeats: components/ReceiveDialog.qml:11-31 (contract: key, isLightning, requestPaid, getPaidTxid; the
// bolt11 / BIP21 URI / address of the request), :65-80 (the QR code of the bolt11, else the URI, else the
// address; tap shows the text), :91-133 (status, message or 'unspecified', amount or 'unspecified'), :150-187
// (Copy: the bolt11 in lower case, else the URI, else the address, then 'Copied!'; Share: the same text, titled
// 'Payment Request' or 'Onchain address'), :191-207 (RequestDetails of the key, requestPaid on Paid or
// Unconfirmed; M3: only on a change to it while the page is open, see _paid), :209-217 (the QR is rendered once
// the page is shown) @ e6df7e1c8; the fiat value of the amount
// as components/controls/FormattedAmount.qml:39-52 @ e6df7e1c8 (timestamp 0).
// Added to the view (same object, no new logic): the expiry of the request (RequestDetails.expiration; 0 or the
// LN_EXPIRY_NEVER delay: 'Never') and the on-chain address as a detail row with the share button.
// Contract for PaymentFlow (as the classic ReceiveDialog): key (set on creation), isLightning, getPaidTxid(),
// requestPaid; plus close() (takes this page off the stack, only when it is on top).
// Strings carried over from ReceiveDialog.qml keep its translation context; 'Copy' / 'Share' (untranslated
// literals in ReceiveDialog.qml) take the context of GenericShareDialog.qml, where they are translated.
M3Page {
    id: root

    readonly property bool m3ReceivePage: true

    title: qsTranslate('ReceiveDialog', 'Receive Payment')

    property string key
    property bool isLightning: request.isLightning

    property string _bolt11: request.bolt11
    property string _bip21uri: request.bip21
    property string _address: request.address
    property bool _render_qr: false // delay qr rendering until the page is shown

    // the QR beside the details only when the details still get a column of 320 (landscape)
    readonly property bool _wide: root.width >= qr.width + 2 * m3.screenMargin(root.width) + m3.space24 + 320
    readonly property string _qrdata: _bolt11
        ? _bolt11
        : _bip21uri
            ? _bip21uri
            : _address

    signal requestPaid

    function getPaidTxid() {
        return request.paidTxid
    }

    // takes only this page off the stack, and only when it is on top
    function close() {
        if (app.stack.currentItem === root)
            app.stack.pop()
        else
            console.log('M3: ReceivePage.close(): the page is not on top, left on the stack')
    }

    // the request is read only once its key is set (Component.onCompleted): before that the getters of
    // RequestDetails have no request (status, expiration raise in Python)
    property bool _ready: false

    // LN_EXPIRY_NEVER of invoices.py (100 years), a delay the core treats as never (invoices.py:91,143)
    readonly property real _lnExpiryNever: 100 * 365 * 24 * 60 * 60
    // M3 (review A-4): the expiry row: 'never', 'date' or '' (no row). RequestDetails.expiration is the date
    // (time + delay; 0 = never, invoices.py get_expiration_date) as a 32-bit int: with the delay LN_EXPIRY_NEVER
    // it wraps (measured: a request of 2026 arrives as a date in 1989), so that delay is compared modulo 2^32;
    // any other date not after the creation time can only be such a wrap (a date after 2038) and is not shown
    readonly property string _expiryKind: !_ready
        ? ''
        : request.expiration == 0 || (request.expiration - request.timestamp - _lnExpiryNever) % 4294967296 == 0
            ? 'never'
            : request.expiration > request.timestamp
                ? 'date'
                : ''

    // status card: colors and icon by the status of the request
    readonly property string _statusStyle: !_ready
        ? 'info'
        : request.status == RequestDetails.Paid
        ? 'done'
        : request.status == RequestDetails.Expired || request.status == RequestDetails.Failed
            ? 'error'
            : request.status == RequestDetails.Unconfirmed || request.status == RequestDetails.Inflight
                || request.status == RequestDetails.Routing
                ? 'progress'
                : request.status == RequestDetails.Unpaid
                    ? 'pending'
                    : 'info'

    property string _fiatText

    // FormattedAmount.qml:45-52 with timestamp 0 (no historic rate; isRecent(0) is true)
    function setFiatValue() {
        if (!_ready || !request.amount)
            return
        _fiatText = Daemon.fx.isRecent(0)
            ? Daemon.fx.fiatValue(request.amount) + ' ' + Daemon.fx.fiatCurrency
            : ''
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            id: flickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentHeight: content.implicitHeight + 2 * m3.space16
            interactive: height < contentHeight
            boundsBehavior: Flickable.StopAtBounds

            GridLayout {
                id: content
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(root._wide ? 2 * m3.maxContentWidth : m3.maxContentWidth,
                                flickable.width - 2 * margin)
                // wide screens: the QR on the left, the details on the right
                columns: root._wide ? 2 : 1
                columnSpacing: m3.space24
                rowSpacing: m3.space16

                // --- QR (ReceiveDialog.qml:53-82) ---
                // M3 (review B-N1, B-N5): the QR is scaled down only when it does not fit: one column - not wider
                // than the column (360 dp: a short URI gives a QR with its frame wider than the column); wide
                // layout - not higher than the visible height, so that a scanner sees it whole without scrolling
                Item {
                    id: qrBox
                    readonly property real fit: qr.width <= 0 || qr.height <= 0
                        ? 1
                        : Math.max(0.5, Math.min(1, root._wide
                            ? (flickable.height - 2 * m3.space16) / qr.height
                            : content.width / qr.width))
                    Layout.alignment: Qt.AlignHCenter | Qt.AlignTop
                    Layout.preferredWidth: Math.floor(qr.width * fit)
                    Layout.preferredHeight: Math.floor(qr.height * fit)

                    M3QRImage {
                        id: qr
                        transformOrigin: Item.TopLeft
                        scale: qrBox.fit
                        qrdata: root._qrdata
                        render: root._render_qr
                        enableToggleText: true
                    }
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignTop
                    spacing: m3.space16

                    // --- status (ReceiveDialog.qml:96-102) ---
                    M3Card {
                        id: statusCard
                        Layout.fillWidth: true
                        visible: statusText.text
                        padding: m3.space12
                        color: root._statusStyle === 'done'
                            ? m3.successContainer
                            : root._statusStyle === 'error'
                                ? m3.errorContainer
                                : m3.secondaryContainer
                        readonly property color onColor: root._statusStyle === 'done'
                            ? m3.successContainerOn
                            : root._statusStyle === 'error'
                                ? m3.errorContainerOn
                                : m3.secondaryContainerOn

                        RowLayout {
                            width: parent.width
                            spacing: m3.space12
                            M3Icon {
                                Layout.alignment: Qt.AlignVCenter
                                color: statusCard.onColor
                                source: root._statusStyle === 'done'
                                    ? Qt.resolvedUrl('../../icons/m3/check_circle.png')
                                    : root._statusStyle === 'error'
                                        ? Qt.resolvedUrl('../../icons/m3/error.png')
                                        : root._statusStyle === 'progress'
                                            ? Qt.resolvedUrl('../../icons/m3/sync.png')
                                            : root._statusStyle === 'pending'
                                                ? Qt.resolvedUrl('../../icons/m3/schedule.png')
                                                : Qt.resolvedUrl('../../icons/m3/info.png')
                            }
                            M3Text {
                                id: statusText
                                Layout.fillWidth: true
                                role: 'bodyLarge'
                                color: statusCard.onColor
                                wrapMode: Text.Wrap
                                text: request.status_str
                            }
                        }
                    }

                    // --- details (ReceiveDialog.qml:103-133) ---
                    M3ListGroup {
                        Layout.fillWidth: true

                        M3DetailRow {
                            label: qsTranslate('ReceiveDialog', 'Amount')
                            readonly property bool known: root._ready && !!request.amount
                            visible: known
                            valueColor: known && request.amount.isEmpty ? m3.surfaceVariantOn : m3.surfaceOn
                            text: !known ? '' : request.amount.isEmpty
                                ? qsTranslate('ReceiveDialog', 'unspecified')
                                : (request.amount.msatsInt != 0
                                    ? Config.formatMilliSats(request.amount)
                                    : Config.formatSats(request.amount))
                                  + ' ' + Config.baseUnit
                                  + (Daemon.fx.enabled && root._fiatText ? '  (' + root._fiatText + ')' : '')
                        }
                        M3DetailRow {
                            label: qsTranslate('ReceiveDialog', 'Message')
                            valueColor: request.message ? m3.surfaceOn : m3.surfaceVariantOn
                            text: request.message ? request.message : qsTranslate('ReceiveDialog', 'unspecified')
                        }
                        M3DetailRow {
                            // a request that never expires: 'Never' (the choice of RequestExpiryComboBox)
                            visible: root._expiryKind !== ''
                            label: root._expiryKind === 'date' && request.status == RequestDetails.Expired
                                ? qsTranslate('InvoicePage', 'Expired')
                                : qsTranslate('InvoicePage', 'Expires')
                            text: root._expiryKind === 'never'
                                ? qsTranslate('RequestExpiryComboBox', 'Never')
                                : root._expiryKind === 'date'
                                    ? new Date(request.expiration * 1000).toLocaleString(Qt.locale(), Locale.ShortFormat)
                                    : ''
                        }
                        M3DetailRow {
                            visible: root._address !== ''
                            label: qsTranslate('InvoiceDialog', 'Address')
                            monospace: true
                            text: root._address
                            shareable: true
                        }
                    }

                    // --- Copy / Share, wide layout (review B-N1): under the details, so that the QR beside
                    // them gets the whole height of the page ---
                    Loader {
                        Layout.fillWidth: true
                        active: root._wide
                        visible: active
                        sourceComponent: actionsComponent
                    }
                }
            }
        }

        // --- Copy / Share, one column: below the content ---
        Rectangle {
            Layout.fillWidth: true
            visible: !root._wide
            implicitHeight: bottomActions.implicitHeight + 2 * m3.space16
            color: m3.surface

            Loader {
                id: bottomActions
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
                active: !root._wide
                sourceComponent: actionsComponent
            }
        }
    }

    // --- Copy / Share (ReceiveDialog.qml:146-188) ---
    Component {
        id: actionsComponent

        RowLayout {
            spacing: m3.space8

            M3Button {
                id: copyButton
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                variant: 'tonal'
                size: 56
                icon.source: Qt.resolvedUrl('../../icons/m3/content_copy.png')
                text: qsTranslate('GenericShareDialog', 'Copy')
                onClicked: {
                    AppController.textToClipboard(_bolt11
                        ? _bolt11.toLowerCase()
                        : _bip21uri
                            ? _bip21uri
                            : _address
                    )
                    toaster.show(this, qsTranslate('ReceiveDialog', 'Copied!'))
                }
            }
            M3Button {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                variant: 'filled'
                size: 56
                icon.source: Qt.resolvedUrl('../../icons/m3/share.png')
                text: qsTranslate('GenericShareDialog', 'Share')
                onClicked: {
                    enabled = false
                    AppController.doShare(
                        _bolt11
                            ? _bolt11.toLowerCase()
                            : _bip21uri
                                ? _bip21uri
                                : _address,
                        _bolt11 || _bip21uri
                            ? qsTranslate('ReceiveDialog', 'Payment Request')
                            : qsTranslate('ReceiveDialog', 'Onchain address')
                    )
                    enabled = true
                }
            }
        }
    }

    // M3 (review A-1, B-N4): requestPaid only for a payment made while the page is open, i.e. a change from a
    // status that is not Paid / Unconfirmed to one that is. A request that was already paid when the page was
    // opened (from the list) shows its status and stays; it does not switch to the details later, when the payment
    // confirms. (The classic dialog went to the details at once in that case.) The status the request has when
    // its key is set (initRequest emits statusChanged inside Component.onCompleted) is only recorded.
    property bool _paid: false

    RequestDetails {
        id: request
        wallet: Daemon.currentWallet
        onStatusChanged: {
            if (!root._ready)
                return
            var paid = status == RequestDetails.Paid || status == RequestDetails.Unconfirmed
            var wasPaid = root._paid
            root._paid = paid
            if (paid && !wasPaid) {
                root.requestPaid()
            }
        }
        onDetailsChanged: root.setFiatValue()
    }

    M3Toaster {
        id: toaster
    }

    Component.onCompleted: {
        request.key = root.key
        _ready = request.amount ? true : false
        _paid = _ready && (request.status == RequestDetails.Paid || request.status == RequestDetails.Unconfirmed)
        setFiatValue()
    }

    // ReceiveDialog.qml:209-217: the QR is rendered once the page is shown (after the push transition)
    StackView.onActivated: root._render_qr = true

    Connections {
        target: Daemon.fx
        function onQuotesUpdated() { root.setFiatValue() }
    }
}
