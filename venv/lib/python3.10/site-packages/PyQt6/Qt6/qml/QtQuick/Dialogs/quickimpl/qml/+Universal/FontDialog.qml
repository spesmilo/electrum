// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.Universal
import QtQuick.Controls.Universal.impl
import QtQuick.Dialogs
import QtQuick.Dialogs.quickimpl
import QtQuick.Layouts
import QtQuick.Templates as T

FontDialogImpl {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding,
                            implicitHeaderWidth,
                            implicitFooterWidth)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding
                             + (implicitHeaderHeight > 0 ? implicitHeaderHeight + spacing : 0)
                             + (implicitFooterHeight > 0 ? implicitFooterHeight + spacing : 0))

    padding: 24
    verticalPadding: 18

    standardButtons: T.Dialog.Ok | T.Dialog.Cancel

    FontDialogImpl.buttonBox: buttonBox
    FontDialogImpl.familyListView: content.familyListView
    FontDialogImpl.styleListView: content.styleListView
    FontDialogImpl.sizeListView: content.sizeListView
    FontDialogImpl.sampleEdit: content.sampleEdit
    FontDialogImpl.writingSystemComboBox: writingSystemComboBox
    FontDialogImpl.underlineCheckBox: content.underline
    FontDialogImpl.strikeoutCheckBox: content.strikeout
    FontDialogImpl.familyEdit: content.familyEdit
    FontDialogImpl.styleEdit: content.styleEdit
    FontDialogImpl.sizeEdit: content.sizeEdit

    background: Rectangle {
        implicitWidth: 600
        implicitHeight: 400
        color: control.Universal.chromeMediumLowColor
        border.color: control.Universal.chromeHighColor
        border.width: 1 // FlyoutBorderThemeThickness
    }

    header: Label {
        text: control.title
        elide: Label.ElideRight
        // TODO: QPlatformTheme::TitleBarFont
        font.pixelSize: 20

        leftPadding: 24
        rightPadding: 24
        topPadding: 18
        height: control.title.length > 0 ? implicitHeight : 0
        visible: content.parent?.parent === Overlay.overlay

        background: Rectangle {
            x: 1; y: 1 // // FlyoutBorderThemeThickness
            color: control.Universal.chromeMediumLowColor
            width: parent.width - 2
            height: parent.height - 1
        }
    }

    contentItem: FontDialogContent {
        id: content
        rowSpacing: 12
    }

    footer: RowLayout {
        id: rowLayout
        spacing: 24

        Label {
            text: qsTr("Writing System")

            Layout.leftMargin: 24
            Layout.topMargin: 6
            Layout.bottomMargin: 24
        }
        ComboBox{
            id: writingSystemComboBox

            Layout.fillWidth: true
            Layout.topMargin: 6
            Layout.bottomMargin: 24

        }

        DialogButtonBox {
            id: buttonBox
            standardButtons: control.standardButtons
            spacing: 12
            horizontalPadding: 0

            Layout.rightMargin: 24
        }
    }

    Overlay.modal: Rectangle {
        color: control.Universal.baseLowColor
    }

    Overlay.modeless: Rectangle {
        color: control.Universal.baseLowColor
    }
}
