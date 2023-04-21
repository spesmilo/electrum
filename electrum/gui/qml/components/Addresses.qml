import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Pane {
    id: rootItem
    objectName: 'Addresses'

    padding: 0

    ColumnLayout {
        id: layout
        anchors.fill: parent

        ListView {
            id: listview

            Layout.fillWidth: true
            Layout.fillHeight: true

            clip: true
            model: Daemon.currentWallet.addressModel
            currentIndex: -1

            section.property: 'type'
            section.criteria: ViewSection.FullString
            section.delegate: sectionDelegate

            delegate: AddressDelegate {
                onClicked: {
                    var page = app.stack.push(Qt.resolvedUrl('AddressDetails.qml'), {'address': model.address})
                    page.addressDetailsChanged.connect(function() {
                        // update listmodel when details change
                        listview.model.update_address(model.address)
                    })
                }
            }

            ScrollIndicator.vertical: ScrollIndicator { }
        }

    }

    Component {
        id: sectionDelegate
        Item {
            id: root
            width: ListView.view.width
            height: childrenRect.height

            required property string section

            ColumnLayout {
                width: parent.width
                Heading {
                    Layout.leftMargin: constants.paddingLarge
                    Layout.rightMargin: constants.paddingLarge
                    text: root.section + ' ' + qsTr('addresses')
                }
            }
        }
    }

    Component.onCompleted: {
        Daemon.currentWallet.addressModel.init_model()
    }
}
