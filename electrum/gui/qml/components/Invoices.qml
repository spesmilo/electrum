import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0
import QtQml.Models 2.1
import QtQml 2.6

import "controls"

Pane {
    id: root

    ColumnLayout {
        anchors.fill: parent

        Label {
            text: qsTr('Invoices')
            font.pixelSize: constants.fontSizeLarge
            color: Material.accentColor
        }

        Rectangle {
            height: 1
            Layout.fillWidth: true
            color: Material.accentColor
        }

        Frame {
            background: PaneInsetBackground {}

            verticalPadding: 0
            horizontalPadding: 0
            Layout.fillHeight: true
            Layout.fillWidth: true

            ListView {
                id: listview
                anchors.fill: parent
                clip: true

                model: DelegateModel {
                    id: delegateModel
                    model: Daemon.currentWallet.invoiceModel
                    delegate: InvoiceDelegate {
                        onClicked: app.stack.getRoot().openInvoice(model.key)
                    }
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
}
