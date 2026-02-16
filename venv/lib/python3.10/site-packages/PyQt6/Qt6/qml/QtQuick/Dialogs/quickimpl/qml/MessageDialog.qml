// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.Basic
import QtQuick.Controls.Basic.impl
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
    leftPadding: 20
    rightPadding: 20

    // Ensure that the background's border is visible.
    leftInset: -1
    rightInset: -1
    topInset: -1
    bottomInset: -1

    spacing: 16

    MessageDialogImpl.buttonBox: buttonBox
    MessageDialogImpl.detailedTextButton: detailedTextButton

    background: Rectangle {
        implicitWidth: 320
        implicitHeight: 160
        color: control.palette.window
        border.color: control.palette.dark
    }

    header: Pane {
        palette.window: control.palette.light
        visible: parent?.parent === Overlay.overlay
        padding: 20

        contentItem: Label {
            width: parent.width
            text: control.title
            visible: control.title.length > 0
            horizontalAlignment: Label.AlignHCenter
            elide: Label.ElideRight
            font.bold: true
        }
    }

    contentItem: Column {
        padding: 10
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

            Layout.leftMargin: 20
            Layout.rightMargin: 20
            Layout.bottomMargin: 20

            Button {
                id: detailedTextButton
                objectName: "detailedTextButton"
                text: control.showDetailedText ? qsTr("Hide Details...") : qsTr("Show Details...")
                padding: 0
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

            Layout.fillWidth: true
            Layout.leftMargin: 20
            Layout.rightMargin: 20
            Layout.bottomMargin: 20

            background: Rectangle {
                color: Qt.rgba(1,1,1,1)
                radius: 3
                border.color: Qt.darker(control.palette.light)
                border.width: 1
            }
        }
    }

    Overlay.modal: Rectangle {
        color: Color.transparent(control.palette.shadow, 0.5)
    }

    Overlay.modeless: Rectangle {
        color: Color.transparent(control.palette.shadow, 0.12)
    }
}
