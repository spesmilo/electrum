// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default


import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.Fusion
import QtQuick.Dialogs
import QtQuick.Dialogs.quickimpl
import QtQuick.Layouts

MessageDialogImpl {
    id: control

    implicitWidth: Math.max(control.implicitBackgroundWidth + control.leftInset + control.rightInset,
                            control.implicitHeaderWidth,
                            rowLayout.implicitWidth)
    implicitHeight: Math.max(control.implicitBackgroundHeight + control.topInset + control.bottomInset,
                             control.implicitContentHeight + control.topPadding + control.bottomPadding
                             + (control.implicitHeaderHeight > 0 ? control.implicitHeaderHeight + control.spacing : 0)
                             + (control.implicitFooterHeight > 0 ? control.implicitFooterHeight + control.spacing : 0))

    padding: 6
    horizontalPadding: 12

    MessageDialogImpl.buttonBox: buttonBox
    MessageDialogImpl.detailedTextButton: detailedTextButton

    background: Rectangle {
        implicitWidth: 320
        implicitHeight: 120
        color: control.palette.window
        border.color: control.palette.mid
        radius: 2

        Rectangle {
            z: -1
            x: 1
            y: 1
            width: parent.width
            height: parent.height
            color: control.palette.shadow
            opacity: 0.2
            radius: 2
        }
    }

    header: Label {
        text: control.title
        visible: parent?.parent === Overlay.overlay
        horizontalAlignment: Label.AlignHCenter
        elide: Label.ElideRight
        font.bold: true
        padding: 6
    }

    contentItem: Column {
        padding: 6
        spacing: 24

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

            Button {
                id: detailedTextButton
                objectName: "detailedTextButton"
                text: control.showDetailedText ? qsTr("Hide Details...") : qsTr("Show Details...")

                Layout.leftMargin: 12
            }

            DialogButtonBox {
                id: buttonBox
                objectName: "buttonBox"
                spacing: 6
                horizontalPadding: 0
                verticalPadding: 12

                Layout.fillWidth: true
                Layout.leftMargin: detailedTextButton.visible ? 6 : 12
                Layout.rightMargin: 12
            }
        }

        TextArea {
            id: detailedTextArea
            objectName: "detailedText"
            text: control.detailedText
            visible: control.showDetailedText
            wrapMode: TextEdit.WordWrap
            readOnly: true

            Layout.fillWidth: true
            Layout.leftMargin: 12
            Layout.rightMargin: 12
            Layout.bottomMargin: 12

            background: Rectangle {
                color: detailedTextArea.palette.base
                radius: 3
                border.color: detailedTextArea.activeFocus ? Fusion.highlightedOutline(detailedTextArea.palette) : Fusion.outline(detailedTextArea.palette)
                border.width: 1
            }
        }
    }

    Overlay.modal: Rectangle {
        color: Fusion.topShadow
    }

    Overlay.modeless: Rectangle {
        color: Fusion.topShadow
    }
}
