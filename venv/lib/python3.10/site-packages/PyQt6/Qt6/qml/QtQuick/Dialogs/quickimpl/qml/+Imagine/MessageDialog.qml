// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.Imagine
import QtQuick.Controls.Imagine.impl
import QtQuick.Dialogs
import QtQuick.Dialogs.quickimpl
import QtQuick.Layouts

MessageDialogImpl {
    id: control

    // Can't set implicitWidth of the NinePatchImage background, so we do it here.
    implicitWidth: Math.max(320,
                            implicitBackgroundWidth + leftInset + rightInset,
                            implicitHeaderWidth,
                            rowLayout.implicitWidth)
    implicitHeight: Math.max(160,
                             implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding
                             + (implicitHeaderHeight > 0 ? implicitHeaderHeight + spacing : 0)
                             + (implicitFooterHeight > 0 ? implicitFooterHeight + spacing : 0))

    topPadding: background ? background.topPadding : 0
    leftPadding: background ? background.leftPadding : 0
    rightPadding: background ? background.rightPadding : 0
    bottomPadding: background ? background.bottomPadding : 0

    topInset: background ? -background.topInset || 0 : 0
    leftInset: background ? -background.leftInset || 0 : 0
    rightInset: background ? -background.rightInset || 0 : 0
    bottomInset: background ? -background.bottomInset || 0 : 0

    MessageDialogImpl.buttonBox: buttonBox
    MessageDialogImpl.detailedTextButton: detailedTextButton

    background: NinePatchImage {
        source: Imagine.url + "dialog-background"
        NinePatchImageSelector on source {
            states: [
                {"modal": control.modal},
                {"dim": control.dim}
            ]
        }
    }

    header: Label {
        text: control.title
        elide: Label.ElideRight
        font.bold: true

        leftPadding: 16
        rightPadding: 16
        topPadding: 12
        visible: parent?.parent === Overlay.overlay && control.title.length > 0

        background: NinePatchImage {
            width: parent.width
            height: parent.height

            source: Imagine.url + "dialog-title"
            NinePatchImageSelector on source {
                states: [
                    {"modal": control.modal},
                    {"dim": control.dim}
                ]
            }
        }
    }

    contentItem: Column {
        padding: 8
        spacing: 16

        Label {
            id: textLabel
            objectName: "textLabel"
            text: control.text
            visible: text.length > 0
            wrapMode: Text.Wrap
            width: parent.width - parent.leftPadding - parent.rightPadding
        }
        Label {
            id: informativeTextLabel
            objectName: "informativeTextLabel"
            text: control.informativeText
            visible: text.length > 0
            wrapMode: Text.Wrap
            width: parent.width - parent.leftPadding - parent.rightPadding
        }
    }

    footer: ColumnLayout {
        id: columnLayout

        RowLayout {
            id: rowLayout
            spacing: 12

            Layout.leftMargin: 16
            Layout.rightMargin: 16
            Layout.bottomMargin: 16

            Button {
                id: detailedTextButton
                objectName: "detailedTextButton"
                text: control.showDetailedText ? qsTr("Hide Details...") : qsTr("Show Details...")
            }

            DialogButtonBox {
                id: buttonBox
                objectName: "buttonBox"
                spacing: 12
                padding: 0

                Layout.fillWidth: true
            }
        }

        TextArea {
            id: detailedTextArea
            objectName: "detailedText"
            text: control.detailedText
            visible: control.showDetailedText
            wrapMode: TextEdit.WordWrap
            readOnly: true

            padding: 12

            Layout.fillWidth: true
            Layout.leftMargin: 16
            Layout.rightMargin: 16
            Layout.bottomMargin: 16

            background: Rectangle {
                color: Qt.rgba(1,1,1,1)
                radius: 3
                border.color: Qt.darker(control.palette.light)
                border.width: 1
            }
        }
    }

    Overlay.modal: NinePatchImage {
        source: Imagine.url + "dialog-overlay"
        NinePatchImageSelector on source {
            states: [
                {"modal": true}
            ]
        }
    }

    Overlay.modeless: NinePatchImage {
        source: Imagine.url + "dialog-overlay"
        NinePatchImageSelector on source {
            states: [
                {"modal": false}
            ]
        }
    }
}
