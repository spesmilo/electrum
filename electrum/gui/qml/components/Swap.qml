import QtQuick 2.6
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Dialog {
    id: root

    width: parent.width
    height: parent.height

    title: qsTr('Lightning Swap')
    standardButtons: Dialog.Cancel

    modal: true
    parent: Overlay.overlay
    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    GridLayout {
        id: layout
        width: parent.width
        height: parent.height
        columns: 2

        Rectangle {
            height: 1
            Layout.fillWidth: true
            Layout.columnSpan: 2
            color: Material.accentColor
        }

        Label {
            text: qsTr('You send')
            color: Material.accentColor
        }

        RowLayout {
            Label {
                id: tosend
                text: Config.formatSats(swaphelper.tosend)
                font.family: FixedFont
                visible: swaphelper.valid
            }
            Label {
                text: Config.baseUnit
                color: Material.accentColor
                visible: swaphelper.valid
            }
            Label {
                text: swaphelper.isReverse ? qsTr('(offchain)') : qsTr('(onchain)')
                visible: swaphelper.valid
            }
        }

        Label {
            text: qsTr('You receive')
            color: Material.accentColor
        }

        RowLayout {
            Layout.fillWidth: true
            Label {
                id: toreceive
                text: Config.formatSats(swaphelper.toreceive)
                font.family: FixedFont
                visible: swaphelper.valid
            }
            Label {
                text: Config.baseUnit
                color: Material.accentColor
                visible: swaphelper.valid
            }
            Label {
                text: swaphelper.isReverse ? qsTr('(onchain)') : qsTr('(offchain)')
                visible: swaphelper.valid
            }
        }

        Label {
            text: qsTr('Server fee')
            color: Material.accentColor
        }

        RowLayout {
            Label {
                text: swaphelper.serverfeeperc
            }
            Label {
                text: Config.formatSats(swaphelper.serverfee)
                font.family: FixedFont
            }
            Label {
                text: Config.baseUnit
                color: Material.accentColor
            }
        }

        Label {
            text: qsTr('Mining fee')
            color: Material.accentColor
        }

        RowLayout {
            Label {
                text: Config.formatSats(swaphelper.miningfee)
                font.family: FixedFont
            }
            Label {
                text: Config.baseUnit
                color: Material.accentColor
            }
        }

        Slider {
            id: swapslider
            Layout.columnSpan: 2
            Layout.preferredWidth: 2/3 * layout.width
            Layout.alignment: Qt.AlignHCenter

            from: swaphelper.rangeMin
            to: swaphelper.rangeMax

            onValueChanged: {
                if (activeFocus)
                    swaphelper.sliderPos = value
            }
            Component.onCompleted: {
                value = swaphelper.sliderPos
            }
            Connections {
                target: swaphelper
                function onSliderPosChanged() {
                    swapslider.value = swaphelper.sliderPos
                }
            }
        }

        InfoTextArea {
            Layout.columnSpan: 2
            visible: swaphelper.userinfo != ''
            text: swaphelper.userinfo
        }

        Rectangle {
            height: 1
            Layout.fillWidth: true
            Layout.columnSpan: 2
            color: Material.accentColor
        }

        Button {
            Layout.alignment: Qt.AlignHCenter
            Layout.columnSpan: 2
            text: qsTr('Ok')
            enabled: swaphelper.valid
            onClicked: swaphelper.executeSwap()
        }

        Item { Layout.fillHeight: true; Layout.preferredWidth: 1; Layout.columnSpan: 2 }
    }

    SwapHelper {
        id: swaphelper
        wallet: Daemon.currentWallet
        onError: {
            var dialog = app.messageDialog.createObject(root, {'text': message})
            dialog.open()
        }
        onConfirm: {
            var dialog = app.messageDialog.createObject(app, {'text': message, 'yesno': true})
            dialog.yesClicked.connect(function() {
                dialog.close()
                swaphelper.executeSwap(true)
                root.close()
            })
            dialog.open()
        }
        onAuthRequired: {
            app.handleAuthRequired(swaphelper, method)
        }
    }
}
