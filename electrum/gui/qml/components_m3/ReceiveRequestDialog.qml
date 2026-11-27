import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// "Create Invoice" of the Material 3 GUI: the parameters of a new payment request, opened by the Receive button
// (PaymentFlow.openReceiveDetailsDialog); replaces the classic ReceiveDetailsDialog.
// repeats: components/ReceiveDetailsDialog.qml:11-150 (the API read by the factory on accept:
// amount, description, expiry, isLightning; the message, amount and expiry fields; Onchain accepts at once;
// Lightning: its enabled condition, then accept on an existing channel, the confirmation of a just-in-time
// channel, or "Amount too low") and components/controls/RequestExpiryComboBox.qml:6-35 (the five
// expiry choices, the initial choice from Config.requestExpiry, else the first; a choice of the user is saved
// to Config.requestExpiry unless it is "Never" (0)).
// Look: an M3Dialog with an outlined message field, M3AmountField (bitcoin and, with fx, fiat), the
// expiry as a choice row, and the two classic buttons Onchain / Lightning as Material 3 buttons.
// Strings carried over keep the translation context of their classic file.
M3Dialog {
    id: dialog

    title: qsTranslate('ReceiveDetailsDialog', 'Create Invoice')

    property alias amount: amountBtc.text
    property alias description: message.text
    property int expiry: _expiryChoices[0].value
    property bool isLightning: false

    // RequestExpiryComboBox.qml:16-20
    readonly property var _expiryChoices: [
        { text: qsTranslate('RequestExpiryComboBox', '10 minutes'), value: 10*60 },
        { text: qsTranslate('RequestExpiryComboBox', '1 hour'), value: 60*60 },
        { text: qsTranslate('RequestExpiryComboBox', '1 day'), value: 24*60*60 },
        { text: qsTranslate('RequestExpiryComboBox', '1 week'), value: 7*24*60*60 },
        { text: qsTranslate('RequestExpiryComboBox', 'Never'), value: 0 }
    ]

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
            spacing: m3.space16

            M3TextField {
                id: message
                Layout.fillWidth: true
                label: qsTranslate('ReceiveDetailsDialog', 'Message')
                // the placeholder of the classic field (the label of an outlined field takes the placeholder's place)
                supportingText: qsTranslate('ReceiveDetailsDialog', 'Description of payment request')
            }

            // the label 'Amount' of the classic form is the label of the field
            M3AmountField {
                id: amountBtc
                Layout.fillWidth: true
            }

            M3SelectRow {
                id: expires
                Layout.fillWidth: true
                leftPadding: 0
                rightPadding: 0
                headline: qsTranslate('ReceiveDetailsDialog', 'Expires after')
                model: dialog._expiryChoices
                currentValue: dialog.expiry
                onSelected: (value) => {
                    dialog.expiry = value
                    // RequestExpiryComboBox.qml:31-34: only a choice of the user, and not "Never"
                    if (value)
                        Config.requestExpiry = value
                }
            }
        }
    }

    buttons: [
        M3Button {
            variant: 'tonal'
            enabled: Daemon.currentWallet.isLightning && (Daemon.currentWallet.lightningCanReceive.satsInt
                        > amountBtc.textAsSats.satsInt || Daemon.currentWallet.canGetZeroconfChannel)
            text: qsTranslate('ReceiveDetailsDialog', 'Lightning')
            icon.source: Qt.resolvedUrl('../../icons/m3/bolt.png')
            onClicked: {
                if (Daemon.currentWallet.lightningCanReceive.satsInt > amountBtc.textAsSats.satsInt) {
                    // can receive on existing channel
                    dialog.isLightning = true
                    doAccept()
                } else if (Daemon.currentWallet.canGetZeroconfChannel && amountBtc.textAsSats.satsInt
                            >= Daemon.currentWallet.minChannelFunding.satsInt) {
                    // ask for confirmation of zeroconf channel to prevent fee surprise
                    var confirmdialog = app.messageDialog.createObject(dialog, {
                        title: qsTranslate('ReceiveDetailsDialog', 'Confirm just-in-time channel'),
                        text: [qsTranslate('ReceiveDetailsDialog', 'Receiving this payment will purchase a Lightning channel from your service provider.'),
                               qsTranslate('ReceiveDetailsDialog', 'Fees will be deducted from the payment.'),
                               qsTranslate('ReceiveDetailsDialog', 'Do you want to continue?')].join(' '),
                        yesno: true
                    })
                    confirmdialog.accepted.connect(function () {
                        dialog.isLightning = true
                        doAccept()
                    })
                    confirmdialog.open()
                } else {
                    // show error that amnt > 200k is necessary to get zeroconf channel
                    var confirmdialog = app.messageDialog.createObject(dialog, {
                        title: qsTranslate('ReceiveDetailsDialog', "Amount too low"),
                        text: [qsTranslate('ReceiveDetailsDialog', "You don't have channels with enough inbound liquidity to receive this payment."),
                               qsTranslate('ReceiveDetailsDialog', "Request at least %1 to open a channel just-in-time.").arg(
                                   Config.formatSats(Daemon.currentWallet.minChannelFunding.satsInt, true))].join(' ')
                    })
                    confirmdialog.open()
                }
                // can't get zeroconf channel and doesn't have enough inbound liquidity
            }
        },
        M3Button {
            variant: 'tonal'
            text: qsTranslate('ReceiveDetailsDialog', 'Onchain')
            icon.source: Qt.resolvedUrl('../../icons/m3/link.png')
            onClicked: { dialog.isLightning = false; doAccept() }
        }
    ]

    // RequestExpiryComboBox.qml:21-27
    Component.onCompleted: {
        for (let i = 0; i < _expiryChoices.length; i++) {
            if (_expiryChoices[i].value == Config.requestExpiry) {
                dialog.expiry = _expiryChoices[i].value
                break
            }
        }
    }
}
