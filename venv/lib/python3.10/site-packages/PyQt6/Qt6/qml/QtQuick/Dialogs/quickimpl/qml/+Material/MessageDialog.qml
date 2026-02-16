// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.Material
import QtQuick.Controls.Material.impl
import QtQuick.Dialogs
import QtQuick.Dialogs.quickimpl
import QtQuick.Layouts

MessageDialogImpl {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding,
                            rowLayout.implicitWidth)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding
                             + (implicitHeaderHeight > 0 ? implicitHeaderHeight + spacing : 0)
                             + (implicitFooterHeight > 0 ? implicitFooterHeight + spacing : 0))

    leftPadding: 24
    rightPadding: 24

    Material.elevation: 24

    MessageDialogImpl.buttonBox: buttonBox
    MessageDialogImpl.detailedTextButton: detailedTextButton

    background: Rectangle {
        implicitWidth: 320
        implicitHeight: 160
        radius: 2
        color: control.Material.dialogColor

        layer.enabled: control.Material.elevation > 0
        layer.effect: ElevationEffect {
            elevation: control.Material.elevation
        }
    }

    header: Label {
        text: control.title
        visible: parent?.parent === Overlay.overlay && control.title.length > 0
        elide: Label.ElideRight
        font.bold: true
        font.pixelSize: 16

        leftPadding: 24
        rightPadding: 24
        topPadding: 24
        bottomPadding: 24
    }

    contentItem: Column {
        spacing: 24
        topPadding: control.parent !== Overlay.overlay ? 24 : 0

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

                Layout.leftMargin: 20
            }

            DialogButtonBox {
                id: buttonBox
                objectName: "buttonBox"
                spacing: 12
                horizontalPadding: 0
                verticalPadding: 20

                Layout.fillWidth: true
                Layout.leftMargin: detailedTextButton.visible ? 12 : 20
                Layout.rightMargin: 20
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
            Layout.leftMargin: 20
            Layout.rightMargin: 20
            Layout.bottomMargin: 20

            background: Rectangle {
                implicitWidth: 120
                implicitHeight: control.Material.textFieldHeight
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
