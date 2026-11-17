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
// Unconfirmed), :209-217 (the QR is rendered once the page is shown) @ e6df7e1c8; the fiat value of the amount
// as components/controls/FormattedAmount.qml:39-52 @ e6df7e1c8 (timestamp 0).
// Added to the view (same object, no new logic): the expiry of the request (RequestDetails.expiration, 0 =
// never: no row) and the on-chain address as a detail row with the share button.
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
                Item {
                    Layout.alignment: Qt.AlignHCenter | Qt.AlignTop
                    Layout.preferredWidth: qr.width
                    Layout.preferredHeight: qr.height

                    M3QRImage {
                        id: qr
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
                            // 0 means never (invoices.py get_expiration_date): no row
                            readonly property bool expires: root._ready && request.expiration > 0
                            visible: expires
                            label: expires && request.status == RequestDetails.Expired
                                ? qsTranslate('InvoicePage', 'Expired')
                                : qsTranslate('InvoicePage', 'Expires')
                            text: expires
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
                }
            }
        }

        // --- Copy / Share (ReceiveDialog.qml:146-188): below the content ---
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: actions.implicitHeight + 2 * m3.space16
            color: m3.surface

            RowLayout {
                id: actions
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
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
    }

    RequestDetails {
        id: request
        wallet: Daemon.currentWallet
        onStatusChanged: {
            if (status == RequestDetails.Paid || status == RequestDetails.Unconfirmed) {
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
        setFiatValue()
    }

    // ReceiveDialog.qml:209-217: the QR is rendered once the page is shown (after the push transition)
    StackView.onActivated: root._render_qr = true

    Connections {
        target: Daemon.fx
        function onQuotesUpdated() { root.setFiatValue() }
    }
}
