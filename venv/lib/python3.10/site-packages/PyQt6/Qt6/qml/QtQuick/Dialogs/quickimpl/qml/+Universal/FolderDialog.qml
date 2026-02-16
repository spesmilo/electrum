// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import Qt.labs.folderlistmodel
import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.Universal
import QtQuick.Controls.Universal.impl
import QtQuick.Dialogs
import QtQuick.Dialogs.quickimpl
import QtQuick.Layouts
import QtQuick.Templates as T

import "." as DialogsImpl

FolderDialogImpl {
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

    standardButtons: T.Dialog.Open | T.Dialog.Cancel

    FolderDialogImpl.folderDialogListView: folderDialogListView
    FolderDialogImpl.breadcrumbBar: breadcrumbBar

    background: Rectangle {
        implicitWidth: 600
        implicitHeight: 400
        color: control.Universal.chromeMediumLowColor
        border.color: control.Universal.chromeHighColor
        border.width: 1 // FlyoutBorderThemeThickness
    }

    header: ColumnLayout {
        spacing: 12

        Label {
            text: control.title
            elide: Label.ElideRight
            // TODO: QPlatformTheme::TitleBarFont
            font.pixelSize: 20
            visible: parent.parent?.parent === Overlay.overlay

            Layout.leftMargin: 24
            Layout.rightMargin: 24
            Layout.topMargin: 18
            Layout.fillWidth: true
            Layout.preferredHeight: control.title.length > 0 ? implicitHeight : 0

            background: Rectangle {
                // FlyoutBorderThemeThickness
                x: 1
                y: 1
                color: control.Universal.chromeMediumLowColor
                width: parent.width - 2
                height: parent.height - 1
            }
        }

        DialogsImpl.FolderBreadcrumbBar {
            id: breadcrumbBar
            dialog: control

            Layout.topMargin: parent.parent?.parent !== Overlay.overlay ? 12 : 0
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            Layout.preferredWidth: 400
            Layout.fillWidth: true
        }
    }

    contentItem: ListView {
        id: folderDialogListView
        objectName: "folderDialogListView"
        clip: true
        boundsBehavior: Flickable.StopAtBounds

        ScrollBar.vertical: ScrollBar {}

        model: FolderListModel {
            folder: control.currentFolder
            showFiles: false
            sortCaseSensitive: false
        }
        delegate: DialogsImpl.FolderDialogDelegate {
            objectName: "folderDialogDelegate" + index
            width: ListView.view.width
            highlighted: ListView.isCurrentItem
            dialog: control
        }
    }

    footer: DialogButtonBox {
        id: buttonBox
        standardButtons: control.standardButtons
        spacing: 12
        leftPadding: 24
        rightPadding: 24
        topPadding: 6
        bottomPadding: 24
        alignment: Qt.AlignRight
    }

    T.Overlay.modal: Rectangle {
        color: control.Universal.baseLowColor
    }

    T.Overlay.modeless: Rectangle {
        color: control.Universal.baseLowColor
    }
}
