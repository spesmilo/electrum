// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import Qt.labs.folderlistmodel
import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.Basic
import QtQuick.Controls.Basic.impl
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

    leftPadding: 20
    rightPadding: 20
    // Ensure that the background's border is visible.
    leftInset: -1
    rightInset: -1
    topInset: -1
    bottomInset: -1

    standardButtons: T.Dialog.Open | T.Dialog.Cancel

    FolderDialogImpl.folderDialogListView: folderDialogListView
    FolderDialogImpl.breadcrumbBar: breadcrumbBar

    background: Rectangle {
        implicitWidth: 600
        implicitHeight: 400
        color: control.palette.window
        border.color: control.palette.dark
    }

    header: Pane {
        palette.window: control.palette.light
        padding: 20

        contentItem: Column {
            spacing: 12

            Label {
                objectName: "dialogTitleBarLabel"
                width: parent.width
                text: control.title
                visible: control.parent === Overlay.overlay && control.title.length > 0
                horizontalAlignment: Label.AlignHCenter
                elide: Label.ElideRight
                font.bold: true
            }

            DialogsImpl.FolderBreadcrumbBar {
                id: breadcrumbBar
                width: parent.width
                dialog: control

                KeyNavigation.tab: folderDialogListView
            }
        }
    }

    contentItem: ListView {
        id: folderDialogListView
        objectName: "folderDialogListView"
        clip: true
        focus: true
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

            KeyNavigation.backtab: breadcrumbBar
            KeyNavigation.tab: control.footer
        }
    }

    footer: DialogButtonBox {
        id: buttonBox
        standardButtons: control.standardButtons
        palette.window: control.palette.light
        spacing: 12
        alignment: Qt.AlignRight
    }

    Overlay.modal: Rectangle {
        color: Color.transparent(control.palette.shadow, 0.5)
    }

    Overlay.modeless: Rectangle {
        color: Color.transparent(control.palette.shadow, 0.12)
    }
}
