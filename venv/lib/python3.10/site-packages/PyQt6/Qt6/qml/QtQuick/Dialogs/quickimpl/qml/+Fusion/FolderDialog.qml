// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import Qt.labs.folderlistmodel
import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.Fusion
import QtQuick.Controls.Fusion.impl
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

    padding: 6
    horizontalPadding: 12

    standardButtons: T.Dialog.Open | T.Dialog.Cancel

    FolderDialogImpl.folderDialogListView: folderDialogListView
    FolderDialogImpl.breadcrumbBar: breadcrumbBar

    background: Rectangle {
        implicitWidth: 600
        implicitHeight: 400
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

    header: ColumnLayout {
        spacing: 0

        Label {
            objectName: "dialogTitleBarLabel"
            text: control.title
            horizontalAlignment: Label.AlignHCenter
            elide: Label.ElideRight
            font.bold: true
            padding: 6
            visible: parent.parent?.parent === Overlay.overlay

            Layout.fillWidth: true
            Layout.leftMargin: 12
            Layout.rightMargin: 12
            Layout.topMargin: control.title.length > 0 ? 0 : 12
            Layout.preferredHeight: control.title.length > 0 ? implicitHeight : 0
        }

        DialogsImpl.FolderBreadcrumbBar {
            id: breadcrumbBar
            dialog: control

            Layout.topMargin: parent.parent?.parent === Overlay.overlay ? 0 : 12
            Layout.fillWidth: true
            Layout.leftMargin: 12
            Layout.rightMargin: 12
            Layout.maximumWidth: parent.width - 24

            KeyNavigation.tab: folderDialogListView
        }
    }

    contentItem: Frame {
        padding: 0
        verticalPadding: 1

        ListView {
            id: folderDialogListView
            objectName: "fileDialogListView"
            anchors.fill: parent
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
                x: 1
                width: ListView.view.width - 2
                highlighted: ListView.isCurrentItem
                dialog: control

                KeyNavigation.backtab: breadcrumbBar
                KeyNavigation.tab: control.footer
            }
        }
    }

    footer: DialogButtonBox {
        id: buttonBox
        standardButtons: control.standardButtons
        spacing: 6
        leftPadding: 0
        rightPadding: 12
        topPadding: 0
        bottomPadding: 12
        background: null
    }

    T.Overlay.modal: Rectangle {
        color: Fusion.topShadow
    }

    T.Overlay.modeless: Rectangle {
        color: Fusion.topShadow
    }
}
