import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQml.Models
import QtQml

import org.electrum 1.0

import "controls"

// "Saved Invoices" of the Material 3 GUI (route app.routes.invoices; replaces the classic Invoices page).
// repeats: components/Invoices.qml:12-119 @ e6df7e1c8 (the press-and-hold hint, the list of
// Daemon.currentWallet.invoiceModel: a tap opens the invoice through the root (openInvoice, then
// invoiceAmountChanged of the opened page re-reads the model) and clears the current item, press and hold makes
// the row current; Delete and View for the current row; the list transitions). The heading of the classic page
// is the title of this page; Delete and View are the actions of the top app bar while a row is current
// (M2-MAP F-3), not a row of buttons below the list. M3: no current row after Delete.
// Strings carried over from Invoices.qml keep its translation context.
M3Page {
    id: root

    title: qsTranslate('Invoices', 'Saved Invoices')

    // actions of the top app bar (main.qml reads `m3Actions`)
    property list<Item> m3Actions: [
        M3IconButton {
            visible: listview.currentIndex >= 0
            icon.source: Qt.resolvedUrl('../../icons/m3/open_in_new.png')
            tooltip: qsTranslate('Invoices', 'View')
            onClicked: {
                var dialog = app.stack.getRoot().openInvoice(listview.currentItem.getKey())
                if (!dialog)  // M3: no page shown (the user is told, PaymentFlow.openInvoice)
                    return
                dialog.invoiceAmountChanged.connect(function () {
                    Daemon.currentWallet.invoiceModel.initModel()
                })
            }
        },
        M3IconButton {
            visible: listview.currentIndex >= 0
            icon.source: Qt.resolvedUrl('../../icons/m3/delete.png')
            tooltip: qsTranslate('Invoices', 'Delete')
            onClicked: {
                Daemon.currentWallet.deleteInvoice(listview.currentItem.getKey())
                // M3 (review A-2, B-N2): no current row after a delete; the ListView would make the next row
                // current and a second tap on Delete would delete it (the classic page does)
                listview.currentIndex = -1
            }
        }
    ]

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        M3InfoText {
            Layout.fillWidth: true
            Layout.topMargin: m3.space16
            Layout.leftMargin: m3.screenMargin(root.width)
            Layout.rightMargin: m3.screenMargin(root.width)
            Layout.bottomMargin: m3.space8
            visible: !Config.userKnowsPressAndHold
            compact: true
            text: qsTranslate('Invoices', 'To access this list from the main screen, press and hold the Send button')
        }

        ListView {
            id: listview
            Layout.alignment: Qt.AlignHCenter
            Layout.fillWidth: true
            Layout.maximumWidth: m3.maxContentWidth
            Layout.fillHeight: true
            clip: true
            currentIndex: -1
            boundsBehavior: Flickable.StopAtBounds

            model: DelegateModel {
                id: delegateModel
                model: Daemon.currentWallet.invoiceModel
                delegate: M3InvoiceDelegate {
                    onClicked: {
                        var dialog = app.stack.getRoot().openInvoice(model.key)
                        listview.currentIndex = -1
                        if (!dialog)  // M3: no page shown (the user is told, PaymentFlow.openInvoice)
                            return
                        dialog.invoiceAmountChanged.connect(function () {
                            Daemon.currentWallet.invoiceModel.initModel()
                        })
                    }
                    onPressAndHold: listview.currentIndex = index
                }
            }

            add: Transition {
                NumberAnimation { properties: 'scale'; from: 0.75; to: 1; duration: 500 }
                NumberAnimation { properties: 'opacity'; from: 0; to: 1; duration: 500 }
            }
            addDisplaced: Transition {
                SpringAnimation { properties: 'y'; duration: 200; spring: 5; damping: 0.5; mass: 2 }
            }

            remove: Transition {
                NumberAnimation { properties: 'scale'; to: 0.75; duration: 300 }
                NumberAnimation { properties: 'opacity'; to: 0; duration: 300 }
            }
            removeDisplaced: Transition {
                SequentialAnimation {
                    PauseAnimation { duration: 200 }
                    SpringAnimation { properties: 'y'; duration: 100; spring: 5; damping: 0.5; mass: 2 }
                }
            }

            ScrollIndicator.vertical: ScrollIndicator { }
        }
    }
}
