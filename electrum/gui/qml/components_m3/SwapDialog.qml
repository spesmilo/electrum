import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// "Lightning Swap" of the Material 3 GUI: the type of the swapDialog component in main.qml (app.startSwap(), from the
// Channels tab, BalanceDetailsPage and the low-reserve banner of the payment flow); main.qml gives it its SwapHelper
// (`swaphelper`, with the handlers of main.qml).
// repeats: components/SwapDialog.qml:10-335: the contract (required `swaphelper`), the user info with
// the icon by the swap state, you send / you receive (the side icons by isReverse), the server fee (mining fee of
// the server + percentage), the mining fee (while valid); the slider from rangeMin to rangeMax with the zero in the
// middle, the "voids" left and right (leftVoid / rightVoid: the part of the range that cannot be chosen), the part
// between the zero and the handle highlighted, enabled in ServiceReady or Failed, the position written to
// swaphelper.sliderPos and read back on sliderPosChanged and at start; "Choose swap provider" for Nostr (enabled
// when not initializing, started or done and there are servers) -> app.nostrSwapServersDialog, on accept a changed
// provider is written to Config.swapServerNPub and setReadyState(); Ok (executeSwap(), while valid and ServiceReady
// or Failed) or Cancel (cancelNormalSwap(), while canCancel); on Success the funding message of the direction, then
// the dialog closes.
// Differences: the provider button uses this dialog's own `swaphelper` (the classic one reaches the id _swaphelper of
// main.qml through the context; it is the same object). Material 3 look: the amounts as rows of a group, the
// slider as a local component (M3SliderRow unchanged) in Material 3 roles (the range
// secondaryContainer, the chosen part primary, the voids outline, the zero mark outline), side icons
// `bolt` for Lightning and `account_balance_wallet` for on-chain (no bitcoin glyph in Material
// Symbols), Ok / Cancel in the bar at the bottom. The slider writes sliderPos on onMoved (a user move only, as the
// classic onValueChanged + activeFocus).
// Strings keep the translation context of the classic file (qsTranslate('SwapDialog', ...)).
M3FullScreenDialog {
    id: root

    required property QtObject swaphelper

    title: qsTranslate('SwapDialog', 'Lightning Swap')
    iconSource: Qt.resolvedUrl('../../icons/m3/swap_horiz.png')

    readonly property url _iconLightning: Qt.resolvedUrl('../../icons/m3/bolt.png')
    readonly property url _iconOnchain: Qt.resolvedUrl('../../icons/m3/account_balance_wallet.png')

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            id: flickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentHeight: content.implicitHeight + 2 * m3.space16
            interactive: height < contentHeight
            boundsBehavior: Flickable.StopAtBounds

            ColumnLayout {
                id: content
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
                spacing: m3.space16

                M3InfoText {
                    id: userinfoText
                    Layout.fillWidth: true
                    visible: swaphelper.userinfo != ''
                    text: swaphelper.userinfo
                    iconStyle: swaphelper.state == SwapHelper.Started || swaphelper.state == SwapHelper.Initializing
                        ? M3InfoText.IconStyle.Spinner
                        : swaphelper.state == SwapHelper.Failed || swaphelper.state == SwapHelper.Cancelled
                            ? M3InfoText.IconStyle.Error
                            : swaphelper.state == SwapHelper.Success
                                ? M3InfoText.IconStyle.Done
                                : swaphelper.state == SwapHelper.NoService
                                    ? M3InfoText.IconStyle.Warn
                                    : M3InfoText.IconStyle.Info
                }

                M3ListGroup {
                    Layout.fillWidth: true

                    SwapRow {
                        label: qsTranslate('SwapDialog', 'You send')
                        icon: swaphelper.isReverse ? root._iconLightning : root._iconOnchain
                        lightning: swaphelper.isReverse
                        value: Config.formatSats(swaphelper.tosend)
                    }
                    SwapRow {
                        label: qsTranslate('SwapDialog', 'You receive')
                        icon: swaphelper.isReverse ? root._iconOnchain : root._iconLightning
                        lightning: !swaphelper.isReverse
                        value: Config.formatSats(swaphelper.toreceive)
                    }
                    SwapRow {
                        label: qsTranslate('SwapDialog', 'Server fee')
                        value: Config.formatSats(swaphelper.serverMiningfee)
                        extra: swaphelper.serverfeeperc
                            ? '+ ' + swaphelper.serverfeeperc
                            : ''
                    }
                    SwapRow {
                        label: qsTranslate('SwapDialog', 'Mining fee')
                        value: Config.formatSats(swaphelper.miningfee)
                        valueVisible: swaphelper.valid
                    }
                }

                SwapSlider {
                    id: swapslider
                    helper: swaphelper
                    Layout.fillWidth: true
                    Layout.topMargin: m3.space8
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: -m3.space8
                    spacing: m3.space8
                    M3Text {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        role: 'labelSmall'
                        color: m3.surfaceVariantOn
                        wrapMode: Text.Wrap
                        text: '\u2190 ' + qsTranslate('SwapDialog', 'Add receiving capacity')
                    }
                    M3Text {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        role: 'labelSmall'
                        color: m3.surfaceVariantOn
                        wrapMode: Text.Wrap
                        horizontalAlignment: Text.AlignRight
                        text: qsTranslate('SwapDialog', 'Add sending capacity') + ' \u2192'
                    }
                }

                M3Button {
                    Layout.alignment: Qt.AlignHCenter
                    visible: swaphelper.isNostr()
                    variant: 'tonal'
                    icon.source: Qt.resolvedUrl('../../icons/m3/dns.png')
                    text: qsTranslate('SwapDialog', 'Choose swap provider')
                    enabled: swaphelper.state != SwapHelper.Initializing
                        && swaphelper.state != SwapHelper.Started
                        && swaphelper.state != SwapHelper.Success
                        && swaphelper.availableSwapServers.count
                    onClicked: {
                        var dialog = app.nostrSwapServersDialog.createObject(app, {
                            swaphelper: swaphelper,
                            selectedPubkey: Config.swapServerNPub
                        })
                        dialog.accepted.connect(function() {
                            if (Config.swapServerNPub != dialog.selectedPubkey) {
                                Config.swapServerNPub = dialog.selectedPubkey
                                swaphelper.setReadyState()
                            }
                        })
                        dialog.open()
                    }
                }
            }
        }

        // SwapDialog.qml:281-307: Ok or Cancel
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: okButton.implicitHeight + 2 * m3.space16
            color: m3.surface

            M3Button {
                id: okButton
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
                variant: 'filled'
                size: 56
                text: qsTranslate('SwapDialog', 'Ok')
                icon.source: Qt.resolvedUrl('../../icons/m3/check.png')
                visible: !swaphelper.canCancel
                enabled: swaphelper.valid && (swaphelper.state == SwapHelper.ServiceReady || swaphelper.state == SwapHelper.Failed)
                onClicked: {
                    swaphelper.executeSwap()
                }
            }
            M3Button {
                x: okButton.x
                width: okButton.width
                anchors.verticalCenter: parent.verticalCenter
                variant: 'outlined'
                size: 56
                text: qsTranslate('SwapDialog', 'Cancel')
                icon.source: Qt.resolvedUrl('../../icons/m3/close.png')
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
                    title: qsTranslate('SwapDialog', 'Success!'),
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

    Component.onCompleted: {
        swapslider.value = swaphelper.sliderPos
    }

    // one amount row: the label with the optional side icon, the amount with the base unit and an optional extra
    // (SwapDialog.qml:55-164)
    component SwapRow: Item {
        id: swapRow
        property string label
        property url icon
        property string value
        property string extra
        property bool valueVisible: true
        property bool lightning: false

        Layout.fillWidth: true
        implicitHeight: Math.max(56, swapRowLayout.implicitHeight + 2 * m3.space8)

        RowLayout {
            id: swapRowLayout
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.leftMargin: m3.space16
            anchors.rightMargin: m3.space16
            anchors.verticalCenter: parent.verticalCenter
            spacing: m3.space8

            M3Text {
                Layout.fillWidth: true
                role: 'bodyLarge'
                wrapMode: Text.Wrap
                text: swapRow.label
            }
            M3Icon {
                visible: swapRow.icon != ''
                size: 20
                source: swapRow.icon
                color: swapRow.lightning ? m3.tertiary : m3.primary
            }
            // the amount with the base unit; the extra (the server percentage) below it
            ColumnLayout {
                Layout.alignment: Qt.AlignVCenter
                spacing: 0
                RowLayout {
                    Layout.alignment: Qt.AlignRight
                    visible: swapRow.valueVisible
                    spacing: m3.space4
                    M3Text {
                        role: 'titleMedium'
                        font.family: FixedFont
                        text: swapRow.value
                    }
                    M3Text {
                        role: 'bodyMedium'
                        color: m3.surfaceVariantOn
                        text: Config.baseUnit
                    }
                }
                M3Text {
                    Layout.alignment: Qt.AlignRight
                    visible: swapRow.extra !== ''
                    role: 'bodyMedium'
                    color: m3.surfaceVariantOn
                    text: swapRow.extra
                }
            }
        }
    }

    // the swap slider (SwapDialog.qml:167-234): the full width is the whole range, the voids at the
    // ends cannot be chosen; the slider itself spans the rest, from rangeMin to rangeMax with the zero mark
    component SwapSlider: Item {
        id: sliderRoot
        property alias value: slider.value
        property QtObject helper

        implicitHeight: slider.implicitHeight

        // the voids: the whole width, below the slider. outline stands apart from the range (secondaryContainer)
        // and from the dialog (surface) in both themes, so the user sees where the range ends (a container role
        // such as surfaceContainerHighest is 1:1 to the range in the light theme); faded with the slider while it
        // is disabled, so a disabled slider does not show the voids stronger than the range
        Rectangle {
            x: slider.leftPadding
            width: parent.width - slider.leftPadding - slider.rightPadding
            anchors.verticalCenter: parent.verticalCenter
            height: 4
            radius: 2
            color: m3.outline
            opacity: slider.opacity
        }

        Slider {
            id: slider
            readonly property real usable: sliderRoot.width - leftPadding - rightPadding
            x: usable * sliderRoot.helper.leftVoid
            width: sliderRoot.width - usable * (sliderRoot.helper.leftVoid + sliderRoot.helper.rightVoid)
            anchors.verticalCenter: parent.verticalCenter

            property real scenter: -slider.from / (slider.to - slider.from)

            enabled: sliderRoot.helper.state == SwapHelper.ServiceReady || sliderRoot.helper.state == SwapHelper.Failed
            opacity: enabled ? 1 : m3.disabledContentOpacity

            from: sliderRoot.helper.rangeMin
            to: sliderRoot.helper.rangeMax

            background: Rectangle {
                x: slider.leftPadding
                y: slider.topPadding + slider.availableHeight / 2 - height / 2
                implicitWidth: 200
                implicitHeight: 4
                width: slider.availableWidth
                height: implicitHeight
                radius: 2
                color: m3.secondaryContainer

                // the chosen part, from the zero to the handle
                Rectangle {
                    x: slider.visualPosition > slider.scenter
                        ? slider.scenter * parent.width
                        : slider.visualPosition * parent.width
                    y: -2
                    width: Math.abs(slider.visualPosition - slider.scenter) * parent.width
                    height: parent.height + 4
                    radius: 4
                    color: m3.primary
                }

                // the zero mark
                Rectangle {
                    x: slider.scenter * parent.width
                    y: -6
                    width: 2
                    height: parent.height + 2 * 6
                    color: m3.outline
                }
            }

            onMoved: {
                sliderRoot.helper.sliderPos = value
            }
        }
    }
}
