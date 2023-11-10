import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQml.Models

import org.electrum 1.0

import "controls"

Pane {
    id: rootItem
    objectName: 'Addresses'

    padding: 0

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        ColumnLayout {
            id: layout
            Layout.fillWidth: true
            Layout.fillHeight: true

            Pane {
                id: filtersPane
                Layout.fillWidth: true
                GridLayout {
                    columns: 3
                    width: parent.width

                    CheckBox {
                        id: showUsed
                        text: qsTr('Show Used')
                        enabled: listview.filterModel.showAddressesCoins != 2
                        onCheckedChanged: {
                            listview.filterModel.showUsed = checked
                            if (activeFocus) {
                                Config.addresslistShowUsed = checked
                            }
                        }
                        Component.onCompleted: {
                            checked = Config.addresslistShowUsed
                            listview.filterModel.showUsed = checked
                        }
                    }

                    RowLayout {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignRight
                        Label {
                            text: qsTr('Show')
                        }
                        ElComboBox {
                            id: showCoinsAddresses
                            textRole: 'text'
                            valueRole: 'value'
                            model: ListModel {
                                id: showCoinsAddressesModel
                                Component.onCompleted: {
                                    // we need to fill the model like this, as ListElement can't evaluate script
                                    showCoinsAddressesModel.append({'text': qsTr('Addresses'), 'value': 1})
                                    showCoinsAddressesModel.append({'text': qsTr('Coins'), 'value': 2})
                                    showCoinsAddressesModel.append({'text': qsTr('Both'), 'value': 3})
                                    listview.filterModel.showAddressesCoins = Config.addresslistShowType
                                    for (let i=0; i < showCoinsAddressesModel.count; i++) {
                                        if (showCoinsAddressesModel.get(i).value == listview.filterModel.showAddressesCoins) {
                                            showCoinsAddresses.currentIndex = i
                                            break
                                        }
                                    }
                                }
                            }
                            onCurrentValueChanged: {
                                if (activeFocus && currentValue) {
                                    listview.filterModel.showAddressesCoins = currentValue
                                    Config.addresslistShowType = currentValue
                                }
                            }
                        }
                    }
                    TextField {
                        id: searchEdit
                        Layout.fillWidth: true
                        Layout.columnSpan: 3
                        placeholderText: qsTr('search')
                        onTextChanged: listview.filterModel.filterText = text
                        Image {
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            source: Qt.resolvedUrl('../../icons/zoom.png')
                            sourceSize.width: constants.iconSizeMedium
                            sourceSize.height: constants.iconSizeMedium
                        }
                    }
                }
            }

            Frame {
                id: channelsFrame
                Layout.fillWidth: true
                Layout.fillHeight: true

                verticalPadding: 0
                horizontalPadding: 0
                background: PaneInsetBackground {}

                ElListView {
                    id: listview

                    anchors.fill: parent
                    clip: true

                    property QtObject backingModel: Daemon.currentWallet.addressCoinModel
                    property QtObject filterModel: Daemon.currentWallet.addressCoinModel.filterModel
                    property bool selectMode: false
                    property bool freeze: true
                    model: visualModel
                    currentIndex: -1

                    section.property: 'type'
                    section.criteria: ViewSection.FullString
                    section.delegate: sectionDelegate

                    function getSelectedItems() {
                        var items = []
                        for (let i = 0; i < selectedGroup.count; i++) {
                            let modelitem = selectedGroup.get(i).model
                            if (modelitem.outpoint)
                                items.push(modelitem.outpoint)
                            else
                                items.push(modelitem.address)
                        }
                        return items
                    }

                    DelegateModel {
                        id: visualModel
                        model: listview.filterModel
                        groups: [
                            DelegateModelGroup {
                                id: selectedGroup;
                                name: 'selected'
                                onCountChanged: {
                                    if (count == 0)
                                        listview.selectMode = false
                                }
                            }
                        ]

                        delegate: Loader {
                            id: loader
                            width: parent.width

                            sourceComponent: model.outpoint ? _coinDelegate : _addressDelegate

                            function toggle() {
                                loader.DelegateModel.inSelected = !loader.DelegateModel.inSelected
                            }

                            Component {
                                id: _addressDelegate
                                AddressDelegate {
                                    id: addressDelegate
                                    width: parent.width
                                    property bool selected: loader.DelegateModel.inSelected
                                    highlighted: selected
                                    onClicked: {
                                        if (!listview.selectMode) {
                                            var page = app.stack.push(Qt.resolvedUrl('AddressDetails.qml'), {
                                                address: model.address
                                            })
                                            page.addressDetailsChanged.connect(function() {
                                                // update listmodel when details change
                                                listview.backingModel.updateAddress(model.address)
                                            })
                                            page.addressDeleted.connect(function() {
                                                // update listmodel when address removed
                                                listview.backingModel.deleteAddress(model.address)
                                            })
                                        } else {
                                            loader.toggle()
                                        }
                                    }
                                    onPressAndHold: {
                                        loader.toggle()
                                        if (!listview.selectMode && selectedGroup.count > 0)
                                            listview.selectMode = true
                                    }
                                }
                            }
                            Component {
                                id: _coinDelegate
                                Pane {
                                    height: coinDelegate.height
                                    padding: 0
                                    background: Rectangle {
                                        color: Qt.darker(constants.darkerBackground, 1.10)
                                    }

                                    CoinDelegate {
                                        id: coinDelegate
                                        width: parent.width
                                        property bool selected: loader.DelegateModel.inSelected
                                        highlighted: selected
                                        indent: listview.filterModel.showAddressesCoins == 2 ? 0 : constants.paddingLarge * 2
                                        onClicked: {
                                            if (!listview.selectMode) {
                                                var page = app.stack.push(Qt.resolvedUrl('TxDetails.qml'), {
                                                    txid: model.txid
                                                })
                                            } else {
                                                loader.toggle()
                                            }
                                        }
                                        onPressAndHold: {
                                            loader.toggle()
                                            if (!listview.selectMode && selectedGroup.count > 0)
                                                listview.selectMode = true
                                        }
                                    }
                                }
                            }
                        }

                    }
                    add: Transition {
                        NumberAnimation { properties: "opacity"; from: 0.0; to: 1.0; duration: 300
                            easing.type: Easing.OutQuad
                        }
                    }

                    onSelectModeChanged: {
                        if (selectMode) {
                            listview.freeze = !selectedGroup.get(0).model.held
                        }
                    }

                    ScrollIndicator.vertical: ScrollIndicator { }
                }
            }
        }

        ButtonContainer {
            Layout.fillWidth: true
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: listview.freeze ? qsTr('Freeze') : qsTr('Unfreeze')
                icon.source: '../../icons/freeze.png'
                visible: listview.selectMode
                onClicked: {
                    var items = listview.getSelectedItems()
                    listview.backingModel.setFrozenForItems(listview.freeze, items)
                    selectedGroup.remove(0, selectedGroup.count)
                }
            }
            // FlatButton {
            //     Layout.fillWidth: true
            //     Layout.preferredWidth: 1
            //     text: qsTr('Pay from...')
            //     icon.source: '../../icons/tab_send.png'
            //     visible: listview.selectMode
            //     enabled: false // TODO
            //     onClicked: {
            //         //
            //     }
            // }
        }

    }

    Component {
        id: sectionDelegate
        Item {
            id: root
            width: ListView.view.width
            height: childrenRect.height
            required property string section
            property string section_label: section == 'receive'
                ? qsTr('receive addresses')
                : section == 'change'
                    ? qsTr('change addresses')
                    : section == 'imported'
                        ? qsTr('imported addresses')
                        : section + ' ' + qsTr('addresses')

            ColumnLayout {
                width: parent.width
                Heading {
                    Layout.leftMargin: constants.paddingLarge
                    Layout.rightMargin: constants.paddingLarge
                    text: root.section_label
                }
            }
        }
    }

    Component.onCompleted: {
        Daemon.currentWallet.addressCoinModel.initModel()
    }
}
