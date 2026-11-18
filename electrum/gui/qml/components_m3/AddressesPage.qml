import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQml.Models

import org.electrum 1.0

import "controls"

// Addresses and coins of the Material 3 GUI (route app.routes.addresses, replaces the classic Addresses page).
// repeats: components/Addresses.qml:11-319: the filters (show used, written to
// Config.addresslistShowUsed only on user action and disabled while only coins are shown; show addresses / coins /
// both, Config.addresslistShowType; the search text of the filter model), the list of
// Daemon.currentWallet.addressCoinModel.filterModel with sections by address type, address rows and coin rows
// (coins indented under addresses when both are shown), a tap opens the address (its details page; the page's
// addressDetailsChanged / addressDeleted update the list model) or the transaction of the coin, press and hold
// selects rows (select mode while any row is selected), Freeze / Unfreeze of the selected rows (the first
// selected row decides which), the model refresh when the page is created and shown again.
// The look is Material 3: the type filter is a segmented button, "Show Used" a filter chip, the search an outlined
// field with the search glyph; rows are M3AddressDelegate / M3CoinDelegate; Freeze / Unfreeze is a button below
// the list while rows are selected.
// Strings carried over from Addresses.qml keep its translation context.
M3Page {
    id: rootItem
    objectName: 'Addresses'

    title: qsTranslate('WalletMainView', 'Addresses/Coins')

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // --- filters (Addresses.qml:26-104) ---
        ColumnLayout {
            id: filters
            readonly property int margin: m3.screenMargin(rootItem.width)
            Layout.alignment: Qt.AlignHCenter
            Layout.fillWidth: true
            Layout.maximumWidth: m3.maxContentWidth
            Layout.leftMargin: margin
            Layout.rightMargin: margin
            Layout.topMargin: m3.space16
            Layout.bottomMargin: m3.space8
            spacing: m3.space12

            M3SegmentedButton {
                id: showCoinsAddresses
                Layout.fillWidth: true
                model: [
                    { text: qsTranslate('Addresses', 'Addresses'), value: 1 },
                    { text: qsTranslate('Addresses', 'Coins'), value: 2 },
                    { text: qsTranslate('Addresses', 'Both'), value: 3 }
                ]
                currentValue: listview.filterModel.showAddressesCoins
                onActivated: (value) => {
                    if (value) {
                        listview.filterModel.showAddressesCoins = value
                        Config.addresslistShowType = value
                    }
                }
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: m3.space8

                M3Chip {
                    id: showUsed
                    Layout.alignment: Qt.AlignVCenter
                    checkable: true
                    text: qsTranslate('Addresses', 'Show Used')
                    iconSource: checked ? Qt.resolvedUrl('../../icons/m3/check.png') : ''
                    enabled: listview.filterModel.showAddressesCoins != 2
                    onToggled: {
                        listview.filterModel.showUsed = checked
                        Config.addresslistShowUsed = checked
                    }
                    Component.onCompleted: {
                        checked = Config.addresslistShowUsed
                        listview.filterModel.showUsed = checked
                    }
                }

                M3TextField {
                    id: searchEdit
                    Layout.fillWidth: true
                    label: qsTranslate('Addresses', 'search')
                    inputMethodHints: Qt.ImhNoPredictiveText

                    onTextChanged: listview.filterModel.filterText = text
                    Component.onCompleted: {
                        text = listview.filterModel.filterText || ''
                        searchEdit.field.rightPadding = 44
                    }

                    M3Icon {
                        parent: searchEdit.field
                        anchors.right: parent.right
                        anchors.rightMargin: m3.space12
                        anchors.verticalCenter: parent.verticalCenter
                        source: Qt.resolvedUrl('../../icons/m3/search.png')
                        color: m3.surfaceVariantOn
                    }
                }
            }
        }

        // --- the list (Addresses.qml:106-248) ---
        ListView {
            id: listview

            Layout.alignment: Qt.AlignHCenter
            Layout.fillWidth: true
            Layout.maximumWidth: m3.maxContentWidth
            Layout.fillHeight: true
            clip: true
            boundsBehavior: Flickable.StopAtBounds

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
                    width: listview.width

                    sourceComponent: model.outpoint ? _coinDelegate : _addressDelegate

                    function toggle() {
                        loader.DelegateModel.inSelected = !loader.DelegateModel.inSelected
                    }

                    Component {
                        id: _addressDelegate
                        M3AddressDelegate {
                            id: addressDelegate
                            width: listview.width
                            property bool selected: loader.DelegateModel.inSelected
                            highlighted: selected
                            onClicked: {
                                if (!listview.selectMode) {
                                    var page = app.pushPage(app.routes.addressDetails, {
                                        address: model.address
                                    })
                                    if (!page)
                                        return
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
                        M3CoinDelegate {
                            id: coinDelegate
                            width: listview.width
                            property bool selected: loader.DelegateModel.inSelected
                            highlighted: selected
                            indent: listview.filterModel.showAddressesCoins == 2 ? 0 : m3.space16 * 2
                            tint: listview.filterModel.showAddressesCoins == 2 ? 'transparent' : m3.surfaceContainerLow
                            onClicked: {
                                if (!listview.selectMode) {
                                    app.pushPage(app.routes.txDetails, {
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

        // --- Freeze / Unfreeze of the selected rows (Addresses.qml:251-277): below the list ---
        Rectangle {
            Layout.fillWidth: true
            visible: listview.selectMode
            implicitHeight: freezeButton.implicitHeight + 2 * m3.space16
            color: m3.surface

            M3Button {
                id: freezeButton
                readonly property int margin: m3.screenMargin(rootItem.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
                variant: 'filled'
                size: 56
                text: listview.freeze ? qsTranslate('Addresses', 'Freeze') : qsTranslate('Addresses', 'Unfreeze')
                icon.source: Qt.resolvedUrl('../../icons/m3/ac_unit.png')
                onClicked: {
                    var items = listview.getSelectedItems()
                    listview.backingModel.setFrozenForItems(listview.freeze, items)
                    selectedGroup.remove(0, selectedGroup.count)
                }
            }
        }
    }

    // Addresses.qml:282-306
    Component {
        id: sectionDelegate
        Item {
            id: root
            width: ListView.view.width
            height: sectionHeader.implicitHeight
            required property string section
            property string section_label: section == 'receive'
                ? qsTranslate('Addresses', 'receive addresses')
                : section == 'change'
                    ? qsTranslate('Addresses', 'change addresses')
                    : section == 'imported'
                        ? qsTranslate('Addresses', 'imported addresses')
                        : section + ' ' + qsTranslate('Addresses', 'addresses')

            M3SectionHeader {
                id: sectionHeader
                width: parent.width
                text: root.section_label
            }
        }
    }

    Component.onCompleted: {
        // Addresses.qml:67 (the type filter starts from the setting)
        listview.filterModel.showAddressesCoins = Config.addresslistShowType
        Daemon.currentWallet.addressCoinModel.initModel()
    }

    StackView.onVisibleChanged: {
        // refresh model if Addresses becomes visible again and the model is dirty,
        // e.g. after a tx was removed in a TxDetails page opened from here.
        if (StackView.visible) {
            Daemon.currentWallet.addressCoinModel.initModel()
        }
    }
}
