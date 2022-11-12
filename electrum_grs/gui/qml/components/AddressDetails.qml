import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Pane {
    id: root
    width: parent.width
    height: parent.height
    padding: 0

    property string address

    signal addressDetailsChanged

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.preferredWidth: parent.width
            Layout.fillHeight: true

            leftMargin: constants.paddingLarge
            rightMargin: constants.paddingLarge
            topMargin: constants.paddingLarge

            contentHeight: rootLayout.height
            clip:true
            interactive: height < contentHeight

            GridLayout {
                id: rootLayout
                width: parent.width

                columns: 2

                Label {
                    text: qsTr('Address')
                    Layout.columnSpan: 2
                    color: Material.accentColor
                }

                TextHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    padding: 0
                    leftPadding: constants.paddingSmall

                    RowLayout {
                        width: parent.width
                        Label {
                            text: root.address
                            font.pixelSize: constants.fontSizeLarge
                            font.family: FixedFont
                            Layout.fillWidth: true
                            wrapMode: Text.Wrap
                        }
                        ToolButton {
                            icon.source: '../../icons/share.png'
                            icon.color: 'transparent'
                            onClicked: {
                                var dialog = app.genericShareDialog.createObject(root,
                                    { title: qsTr('Address'), text: root.address }
                                )
                                dialog.open()
                            }
                        }
                    }
                }

                Label {
                    text: qsTr('Label')
                    Layout.columnSpan: 2
                    color: Material.accentColor
                }

                TextHighlightPane {
                    id: labelContent

                    property bool editmode: false

                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    padding: 0
                    leftPadding: constants.paddingSmall

                    RowLayout {
                        width: parent.width
                        Label {
                            visible: !labelContent.editmode
                            text: addressdetails.label
                            wrapMode: Text.Wrap
                            Layout.fillWidth: true
                            font.pixelSize: constants.fontSizeLarge
                        }
                        ToolButton {
                            visible: !labelContent.editmode
                            icon.source: '../../icons/pen.png'
                            icon.color: 'transparent'
                            onClicked: {
                                labelEdit.text = addressdetails.label
                                labelContent.editmode = true
                                labelEdit.focus = true
                            }
                        }
                        TextField {
                            id: labelEdit
                            visible: labelContent.editmode
                            text: addressdetails.label
                            font.pixelSize: constants.fontSizeLarge
                            Layout.fillWidth: true
                        }
                        ToolButton {
                            visible: labelContent.editmode
                            icon.source: '../../icons/confirmed.png'
                            icon.color: 'transparent'
                            onClicked: {
                                labelContent.editmode = false
                                addressdetails.set_label(labelEdit.text)
                            }
                        }
                        ToolButton {
                            visible: labelContent.editmode
                            icon.source: '../../icons/closebutton.png'
                            icon.color: 'transparent'
                            onClicked: labelContent.editmode = false
                        }
                    }
                }

                Label {
                    text: qsTr('Public keys')
                    Layout.columnSpan: 2
                    color: Material.accentColor
                }

                Repeater {
                    model: addressdetails.pubkeys
                    delegate: TextHighlightPane {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        padding: 0
                        leftPadding: constants.paddingSmall
                        RowLayout {
                            width: parent.width
                            Label {
                                text: modelData
                                Layout.fillWidth: true
                                wrapMode: Text.Wrap
                                font.pixelSize: constants.fontSizeLarge
                                font.family: FixedFont
                            }
                            ToolButton {
                                icon.source: '../../icons/share.png'
                                icon.color: 'transparent'
                                onClicked: {
                                    var dialog = app.genericShareDialog.createObject(root,
                                        { title: qsTr('Public key'), text: modelData }
                                    )
                                    dialog.open()
                                }
                            }
                        }
                    }
                }

                Label {
                    text: qsTr('Script type')
                    color: Material.accentColor
                }

                Label {
                    text: addressdetails.scriptType
                    Layout.fillWidth: true
                }

                Label {
                    text: qsTr('Balance')
                    color: Material.accentColor
                }

                RowLayout {
                    Label {
                        font.family: FixedFont
                        text: Config.formatSats(addressdetails.balance)
                    }
                    Label {
                        color: Material.accentColor
                        text: Config.baseUnit
                    }
                    Label {
                        text: Daemon.fx.enabled
                            ? '(' + Daemon.fx.fiatValue(addressdetails.balance) + ' ' + Daemon.fx.fiatCurrency + ')'
                            : ''
                    }
                }

                Label {
                    text: qsTr('Transactions')
                    color: Material.accentColor
                }

                Label {
                    text: addressdetails.numTx
                }

                Label {
                    text: qsTr('Derivation path')
                    color: Material.accentColor
                }

                Label {
                    text: addressdetails.derivationPath
                }

                Label {
                    text: qsTr('Frozen')
                    color: Material.accentColor
                }

                Label {
                    text: addressdetails.isFrozen ? qsTr('Frozen') : qsTr('Not frozen')
                }
            }
        }

        FlatButton {
            Layout.fillWidth: true
            text: addressdetails.isFrozen ? qsTr('Unfreeze address') : qsTr('Freeze address')
            onClicked: addressdetails.freeze(!addressdetails.isFrozen)
            icon.source: '../../icons/seal.png'
        }
    }

    AddressDetails {
        id: addressdetails
        wallet: Daemon.currentWallet
        address: root.address
        onFrozenChanged: addressDetailsChanged()
        onLabelChanged: addressDetailsChanged()
    }
}
