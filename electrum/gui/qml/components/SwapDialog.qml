import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: root

    required property QtObject swaphelper

    implicitHeight: parent.height
    implicitWidth: parent.width

    title: qsTr('Lightning Swap')
    iconSource: Qt.resolvedUrl('../../icons/update.png')

    padding: 0

    ColumnLayout {
        width: parent.width
        height: parent.height
        spacing: constants.paddingLarge

        InfoTextArea {
            id: userinfoText
            Layout.leftMargin: constants.paddingXXLarge
            Layout.rightMargin: constants.paddingXXLarge
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignHCenter
            visible: swaphelper.userinfo != ''
            text: swaphelper.userinfo
            iconStyle: swaphelper.state == SwapHelper.Started || swaphelper.state == SwapHelper.Initializing
                ? InfoTextArea.IconStyle.Spinner
                : swaphelper.state == SwapHelper.Failed || swaphelper.state == SwapHelper.Cancelled
                    ? InfoTextArea.IconStyle.Error
                    : swaphelper.state == SwapHelper.Success
                        ? InfoTextArea.IconStyle.Done
                        : swaphelper.state == SwapHelper.NoService
                            ? InfoTextArea.IconStyle.Warn
                            : InfoTextArea.IconStyle.Info
        }

        GridLayout {
            id: layout
            columns: 2
            Layout.preferredWidth: parent.width
            Layout.leftMargin: constants.paddingXXLarge
            Layout.rightMargin: constants.paddingXXLarge

            RowLayout {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                Label {
                    Layout.preferredWidth: 1
                    Layout.fillWidth: true
                    text: qsTr('You send')
                    color: Material.accentColor
                }
                Image {
                    Layout.preferredWidth: constants.iconSizeSmall
                    Layout.preferredHeight: constants.iconSizeSmall
                    source: swaphelper.isReverse
                        ? '../../icons/lightning.png'
                        : '../../icons/bitcoin.png'
                }
            }

            RowLayout {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                Label {
                    id: tosend
                    text: Config.formatSats(swaphelper.tosend)
                    font.family: FixedFont
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                }
            }

            RowLayout {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                Label {
                    Layout.preferredWidth: 1
                    Layout.fillWidth: true
                    text: qsTr('You receive')
                    color: Material.accentColor
                }
                Image {
                    Layout.preferredWidth: constants.iconSizeSmall
                    Layout.preferredHeight: constants.iconSizeSmall
                    source: swaphelper.isReverse
                        ? '../../icons/bitcoin.png'
                        : '../../icons/lightning.png'
                }
            }

            RowLayout {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                Label {
                    id: toreceive
                    text: Config.formatSats(swaphelper.toreceive)
                    font.family: FixedFont
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                }
            }

            Label {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                text: qsTr('Server fee')
                color: Material.accentColor
            }

            RowLayout {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                Label {
                    text: Config.formatSats(swaphelper.serverMiningfee)
                    font.family: FixedFont
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                }
                Label {
                    text: swaphelper.serverfeeperc
                        ? '+ ' + swaphelper.serverfeeperc
                        : ''
                }
            }

            Label {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                text: qsTr('Mining fee')
                color: Material.accentColor
            }

            RowLayout {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                Label {
                    text: Config.formatSats(swaphelper.miningfee)
                    font.family: FixedFont
                    visible: swaphelper.valid
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                    visible: swaphelper.valid
                }
            }
        }

        Slider {
            id: swapslider
            Layout.fillWidth: true

            Layout.topMargin: constants.paddingLarge
            Layout.bottomMargin: constants.paddingLarge
            Layout.leftMargin: constants.paddingXXLarge + (parent.width - 2 * constants.paddingXXLarge) * swaphelper.leftVoid
            Layout.rightMargin: constants.paddingXXLarge + (parent.width - 2 * constants.paddingXXLarge) * swaphelper.rightVoid

            property real scenter: -swapslider.from / (swapslider.to - swapslider.from)

            enabled: swaphelper.state == SwapHelper.ServiceReady || swaphelper.state == SwapHelper.Failed

            background: Rectangle {
                x: swapslider.leftPadding
                y: swapslider.topPadding + swapslider.availableHeight / 2 - height / 2
                implicitWidth: 200
                implicitHeight: 4
                width: swapslider.availableWidth
                height: implicitHeight
                radius: 2
                color: enabled
                    ? Material.accentColor
                    : Material.sliderDisabledColor

                // full width somehow misaligns with handle, define rangeWidth
                property int rangeWidth: width - swapslider.leftPadding

                Rectangle {
                    x: swapslider.visualPosition > swapslider.scenter
                        ? swapslider.scenter * parent.rangeWidth
                        : swapslider.visualPosition * parent.rangeWidth
                    y: enabled ? -1 : 0
                    width: swapslider.visualPosition > swapslider.scenter
                        ? (swapslider.visualPosition-swapslider.scenter) * parent.rangeWidth
                        : (swapslider.scenter-swapslider.visualPosition) * parent.rangeWidth
                    height: enabled ? parent.height + 2 : parent.height
                    color: enabled
                        ? constants.colorOk
                        : Material.sliderDisabledColor
                }

                Rectangle {
                    x: - (swapslider.parent.width - 2 * constants.paddingXXLarge) * swaphelper.leftVoid
                    z: -1
                    // width makes rectangle go outside the control, into the Layout margins
                    width: swapslider.parent.width - 2 * constants.paddingXXLarge - swapslider.leftPadding - swapslider.rightPadding
                    height: parent.height
                    color: Material.sliderDisabledColor
                }

                Rectangle {
                    x: swapslider.scenter * parent.rangeWidth
                    y: -4
                    width: 1
                    height: parent.height + 2*4
                    color: parent.color
                }
            }

            from: swaphelper.rangeMin
            to: swaphelper.rangeMax

            onValueChanged: {
                if (activeFocus)
                    swaphelper.sliderPos = value
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: -constants.paddingXXLarge
            Layout.leftMargin: constants.paddingXXLarge + swapslider.leftPadding
            Layout.rightMargin: constants.paddingXXLarge + swapslider.rightPadding
            Label {
                text: '<-- ' + qsTr('Add receiving capacity')
                font.pixelSize: constants.fontSizeXSmall
                color: Material.accentColor
            }
            Label {
                Layout.fillWidth: true
                horizontalAlignment: Text.AlignRight
                text: qsTr('Add sending capacity') + ' -->'
                font.pixelSize: constants.fontSizeXSmall
                color: Material.accentColor
            }
        }


        Pane {
            Layout.alignment: Qt.AlignHCenter
            visible: _swaphelper.isNostr()
            background: Rectangle { color: constants.darkerDialogBackground }
            padding: 0

            FlatButton {
                text: qsTr('Choose swap provider')
                enabled: _swaphelper.state != SwapHelper.Initializing
                    && _swaphelper.state != SwapHelper.Success
                    && _swaphelper.availableSwapServers.count
                onClicked: {
                    var dialog = app.nostrSwapServersDialog.createObject(app, {
                        swaphelper: _swaphelper,
                        selectedPubkey: Config.swapServerNPub
                    })
                    dialog.accepted.connect(function() {
                        if (Config.swapServerNPub != dialog.selectedPubkey) {
                            Config.swapServerNPub = dialog.selectedPubkey
                            _swaphelper.setReadyState()
                        }
                    })
                    dialog.open()
                }
            }
        }

        Item { Layout.fillHeight: true; Layout.preferredWidth: 1 }

        ButtonContainer {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Ok')
                icon.source: Qt.resolvedUrl('../../icons/confirmed.png')
                visible: !swaphelper.canCancel
                enabled: swaphelper.valid && (swaphelper.state == SwapHelper.ServiceReady || swaphelper.state == SwapHelper.Failed)

                onClicked: {
                    if (swaphelper.isReverse) {
                        swaphelper.executeSwap()
                    } else {
                        swaphelper.prepNormalSwap()
                        var dialog = forwardSwapTxDialog.createObject(app, {
                            finalizer: swaphelper.finalizer,
                            satoshis: swaphelper.finalizer.amount
                        })
                        dialog.accepted.connect(function() {
                            swaphelper.executeSwap()
                        })
                        dialog.open()
                    }
                }
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Cancel')
                icon.source: Qt.resolvedUrl('../../icons/closebutton.png')
                visible: swaphelper.canCancel

                onClicked: {
                    swaphelper.cancelNormalSwap()
                }
            }
        }
    }

    Connections {
        target: swaphelper
        function onSliderPosChanged() {
            swapslider.value = swaphelper.sliderPos
        }
        function onStateChanged() {
            if (swaphelper.state == SwapHelper.Success) {
                var dialog = app.messageDialog.createObject(app, {
                    title: qsTr('Success!'),
                    text: Config.getTranslatedMessage(swaphelper.isReverse
                            ? 'MSG_REVERSE_SWAP_FUNDING_MEMPOOL'
                            : 'MSG_FORWARD_SWAP_FUNDING_MEMPOOL')
                })
                dialog.accepted.connect(function() {
                    Qt.callLater(root.close)
                })
                dialog.open()
            }
        }
    }

    Component {
        id: forwardSwapTxDialog
        ConfirmTxDialog {
            amountLabelText: qsTr('Amount to swap')
            sendButtonText: qsTr('Swap')
            finalizer: swaphelper.finalizer
        }
    }

    Component.onCompleted: {
        swapslider.value = swaphelper.sliderPos
    }

}
