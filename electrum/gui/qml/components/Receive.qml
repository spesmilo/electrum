import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0
import QtQml.Models 2.1

import org.electrum 1.0

Pane {
    id: rootItem
    visible: Daemon.currentWallet !== undefined

    GridLayout {
        id: form
        width: parent.width
        rowSpacing: constants.paddingSmall
        columnSpacing: constants.paddingSmall
        columns: 4

        Label {
            text: qsTr('Message')
        }

        TextField {
            id: message
            placeholderText: qsTr('Description of payment request')
            Layout.columnSpan: 3
            Layout.fillWidth: true
        }

        Label {
            text: qsTr('Request')
            wrapMode: Text.WordWrap
            Layout.rightMargin: constants.paddingXLarge
        }

        TextField {
            id: amount
            font.family: FixedFont
            Layout.preferredWidth: parent.width /2
            placeholderText: qsTr('Amount')
            inputMethodHints: Qt.ImhPreferNumbers

            property string textAsSats
            onTextChanged: {
                textAsSats = Config.unitsToSats(amount.text)
                if (amountFiat.activeFocus)
                    return
                amountFiat.text = Daemon.fx.fiatValue(amount.textAsSats)
            }

            Connections {
                target: Config
                function onBaseUnitChanged() {
                    amount.text = amount.textAsSats != 0 ? Config.satsToUnits(amount.textAsSats) : ''
                }
            }
        }

        Label {
            text: Config.baseUnit
            color: Material.accentColor
        }

        Item { width: 1; height: 1; Layout.fillWidth: true }

        Item { visible: Daemon.fx.enabled; width: 1; height: 1 }

        TextField {
            id: amountFiat
            visible: Daemon.fx.enabled
            font.family: FixedFont
            Layout.preferredWidth: parent.width /2
            placeholderText: qsTr('Amount')
            inputMethodHints: Qt.ImhDigitsOnly
            onTextChanged: {
                if (amountFiat.activeFocus)
                    amount.text = text == '' ? '' : Config.satsToUnits(Daemon.fx.satoshiValue(amountFiat.text))
            }
        }

        Label {
            visible: Daemon.fx.enabled
            text: Daemon.fx.fiatCurrency
            color: Material.accentColor
        }

        Item { visible: Daemon.fx.enabled; width: 1; height: 1; Layout.fillWidth: true }

        Label {
            text: qsTr('Expires after')
            Layout.fillWidth: false
        }

        ComboBox {
            id: expires
            Layout.columnSpan: 2

            textRole: 'text'
            valueRole: 'value'

            model: ListModel {
                id: expiresmodel
                Component.onCompleted: {
                    // we need to fill the model like this, as ListElement can't evaluate script
                    expiresmodel.append({'text': qsTr('10 minutes'), 'value': 10*60})
                    expiresmodel.append({'text': qsTr('1 hour'), 'value': 60*60})
                    expiresmodel.append({'text': qsTr('1 day'), 'value': 24*60*60})
                    expiresmodel.append({'text': qsTr('1 week'), 'value': 7*24*60*60})
                    expiresmodel.append({'text': qsTr('1 month'), 'value': 31*7*24*60*60})
                    expiresmodel.append({'text': qsTr('Never'), 'value': 0})
                    expires.currentIndex = 0
                }
            }

            // redefine contentItem, as the default crops the widest item
            contentItem: Label {
                text: expires.currentText
                padding: constants.paddingLarge
                font.pixelSize: constants.fontSizeMedium
            }
        }

        Item { width: 1; height: 1; Layout.fillWidth: true }

        Button {
            Layout.columnSpan: 4
            Layout.alignment: Qt.AlignHCenter
            text: qsTr('Create Request')
            onClicked: {
                createRequest()
            }
        }
    }

    Frame {
        verticalPadding: 0
        horizontalPadding: 0

        anchors {
            top: form.bottom
            topMargin: constants.paddingXLarge
            left: parent.left
            right: parent.right
            bottom: parent.bottom
        }

        background: PaneInsetBackground {}

        ColumnLayout {
            spacing: 0
            anchors.fill: parent

            Item {
                Layout.preferredHeight: hitem.height
                Layout.preferredWidth: parent.width
                Rectangle {
                    anchors.fill: parent
                    color: Qt.lighter(Material.background, 1.25)
                }
                RowLayout {
                    id: hitem
                    width: parent.width
                    Label {
                        text: qsTr('Receive queue')
                        font.pixelSize: constants.fontSizeXLarge
                    }
                }
            }

            ListView {
                id: listview
                Layout.fillHeight: true
                Layout.fillWidth: true
                clip: true

                model: DelegateModel {
                    id: delegateModel
                    model: Daemon.currentWallet.requestModel

                    delegate: ItemDelegate {
                        id: root
                        height: item.height
                        width: ListView.view.width

                        onClicked: {
                            var dialog = requestdialog.createObject(app, {'modelItem': model})
                            dialog.open()
                        }

                        font.pixelSize: constants.fontSizeSmall // set default font size for child controls

                        GridLayout {
                            id: item

                            anchors {
                                left: parent.left
                                right: parent.right
                                leftMargin: constants.paddingSmall
                                rightMargin: constants.paddingSmall
                            }

                            columns: 5

                            Rectangle {
                                Layout.columnSpan: 5
                                Layout.fillWidth: true
                                Layout.preferredHeight: constants.paddingTiny
                                color: 'transparent'
                            }
                            Image {
                                Layout.rowSpan: 2
                                Layout.preferredWidth: constants.iconSizeLarge
                                Layout.preferredHeight: constants.iconSizeLarge
                                source: model.type == 0 ? "../../icons/bitcoin.png" : "../../icons/lightning.png"
                            }
                            Label {
                                Layout.fillWidth: true
                                Layout.columnSpan: 2
                                text: model.message
                                elide: Text.ElideRight
                                font.pixelSize: constants.fontSizeLarge
                            }

                            Label {
                                text: qsTr('Amount: ')
                            }
                            Label {
                                id: amount
                                text: Config.formatSats(model.amount, true)
                                font.family: FixedFont
                            }

                            Label {
                                text: qsTr('Timestamp: ')
                            }
                            Label {
                                text: model.date
                            }

                            Label {
                                text: qsTr('Status: ')
                            }
                            Label {
                                text: model.status
                            }
                            Rectangle {
                                Layout.columnSpan: 5
                                Layout.fillWidth: true
                                Layout.preferredHeight: constants.paddingTiny
                                color: 'transparent'
                            }
                        }

                        Connections {
                            target: Config
                            function onBaseUnitChanged() {
                                amount.text = Config.formatSats(model.amount, true)
                            }
                            function onThousandsSeparatorChanged() {
                                amount.text = Config.formatSats(model.amount, true)
                            }
                        }

                    }

                }

                remove: Transition {
                    NumberAnimation { properties: 'scale'; to: 0; duration: 400 }
                    NumberAnimation { properties: 'opacity'; to: 0; duration: 300 }
                }
                removeDisplaced: Transition {
                    SpringAnimation { properties: 'y'; duration: 100; spring: 5; damping: 0.5; mass: 2 }
                }

                ScrollIndicator.vertical: ScrollIndicator { }
            }
        }
    }

    // make clicking the dialog background move the scope away from textedit fields
    // so the keyboard goes away
    MouseArea {
        anchors.fill: parent
        z: -1000
        onClicked: parkFocus.focus = true
        FocusScope { id: parkFocus }
    }

    Component {
        id: requestdialog
        RequestDialog {}
    }

    function createRequest(ignoreGaplimit = false) {
        var a = Config.unitsToSats(amount.text)
        Daemon.currentWallet.create_request(a, message.text, expires.currentValue, false, ignoreGaplimit)
    }

    Connections {
        target: Daemon.currentWallet
        function onRequestCreateSuccess() {
            message.text = ''
            amount.text = ''
            var dialog = requestdialog.createObject(app, {
                'modelItem': delegateModel.items.get(0).model
            })
            dialog.open()
        }
        function onRequestCreateError(code, error) {
            if (code == 'gaplimit') {
                var dialog = app.messageDialog.createObject(app, {'text': error, 'yesno': true})
                dialog.yesClicked.connect(function() {
                    createRequest(true)
                })
            } else {
                console.log(error)
                var dialog = app.messageDialog.createObject(app, {'text': error})
            }
            dialog.open()
        }
        function onRequestStatusChanged(key, status) {
            Daemon.currentWallet.requestModel.updateRequest(key, status)
        }
    }

    Connections {
        target: Daemon.fx
        function onQuotesUpdated() {
            var a = Config.unitsToSats(amount.text)
            amountFiat.text = Daemon.fx.fiatValue(a)
        }
    }

}
