// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.Universal
import QtQuick.Dialogs
import QtQuick.Dialogs.quickimpl
import QtQuick.Layouts

MessageDialogImpl {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitHeaderWidth,
                            rowLayout.implicitWidth)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding
                             + (implicitHeaderHeight > 0 ? implicitHeaderHeight + spacing : 0)
                             + (implicitFooterHeight > 0 ? implicitFooterHeight + spacing : 0))

    padding: 24
    verticalPadding: 18

    MessageDialogImpl.buttonBox: buttonBox
    MessageDialogImpl.detailedTextButton: detailedTextButton

    background: Rectangle {
        implicitWidth: 320
        implicitHeight: 160
        color: control.Universal.chromeMediumLowColor
        border.color: control.Universal.chromeHighColor
        border.width: 1 // FlyoutBorderThemeThickness
    }

    header: Label {
        text: control.title
        elide: Label.ElideRight
        // TODO: QPlatformTheme::TitleBarFont
        font.pixelSize: 20
        visible: parent?.parent === Overlay.overlay && control.title.length > 0

        leftPadding: 24
        rightPadding: 24
        topPadding: 18

        background: Rectangle {
            x: 1; y: 1 // // FlyoutBorderThemeThickness
            color: control.Universal.chromeMediumLowColor
            width: parent.width - 2
            height: parent.height - 1
        }
    }

    contentItem: Column {
        spacing: 24

        Label {
            id: textLabel
            objectName: "textLabel"
            text: control.text
            visible: text.length > 0
            wrapMode: Text.Wrap
            width: parent.width
        }

        Label {
            id: informativeTextLabel
            objectName: "informativeTextLabel"
            text: control.informativeText
            visible: text.length > 0
            wrapMode: Text.Wrap
            width: parent.width
        }
    }

    footer: ColumnLayout {
        id: columnLayout

        RowLayout {
            id: rowLayout
            spacing: 12

            Layout.margins: 20

            Button {
                id: detailedTextButton
                objectName: "detailedTextButton"
                text: control.showDetailedText ? qsTr("Hide Details...") : qsTr("Show Details...")
            }

            DialogButtonBox {
                id: buttonBox
                objectName: "buttonBox"
                spacing: 12
                horizontalPadding: 0
                topPadding: 0
                bottomPadding: 0

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
                implicitWidth: 60 // TextControlThemeMinWidth - 4 (border)
                implicitHeight: 28 // TextControlThemeMinHeight - 4 (border)
                color: Qt.rgba(1,1,1,1)
                radius: 3
                border.color: Qt.darker(control.palette.light)
                border.width: 1
            }
        }
    }

    Overlay.modal: Rectangle {
        color: control.Universal.baseLowColor
    }

    Overlay.modeless: Rectangle {
        color: control.Universal.baseLowColor
    }
}
