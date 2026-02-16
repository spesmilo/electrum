// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import Qt.labs.folderlistmodel
import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Imagine
import QtQuick.Controls.Imagine.impl
import QtQuick.Dialogs.quickimpl
import QtQuick.Layouts

import "." as DialogsImpl

FolderDialogImpl {
    id: control

    // Can't set implicitWidth of the NinePatchImage background, so we do it here.
    implicitWidth: Math.max(600,
                            implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding,
                            implicitHeaderWidth,
                            implicitFooterWidth)
    implicitHeight: Math.max(400,
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

    standardButtons: T.Dialog.Open | T.Dialog.Cancel

    FolderDialogImpl.folderDialogListView: folderDialogListView
    FolderDialogImpl.breadcrumbBar: breadcrumbBar

    background: NinePatchImage {
        source: Imagine.url + "dialog-background"
        NinePatchImageSelector on source {
            states: [
                {"modal": control.modal},
                {"dim": control.dim}
            ]
        }
    }

    header: ColumnLayout {
        spacing: 12

        Label {
            text: control.title
            elide: Label.ElideRight
            font.bold: true
            visible: parent.parent?.parent === Overlay.overlay

            Layout.leftMargin: 16
            Layout.rightMargin: 16
            Layout.topMargin: 12
            Layout.fillWidth: true
            Layout.preferredHeight: control.title.length > 0 ? implicitHeight : 0

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

        DialogsImpl.FolderBreadcrumbBar {
            id: breadcrumbBar
            dialog: control

            Layout.topMargin: parent.parent?.parent === Overlay.overlay ? 12 : 0
            Layout.leftMargin: 16
            Layout.rightMargin: 16
            Layout.fillWidth: true
            Layout.maximumWidth: parent.width - 28
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
        leftPadding: 16
        rightPadding: 16
        bottomPadding: 16
    }

    T.Overlay.modal: NinePatchImage {
        source: Imagine.url + "dialog-overlay"
        NinePatchImageSelector on source {
            states: [
                {"modal": true}
            ]
        }
    }

    T.Overlay.modeless: NinePatchImage {
        source: Imagine.url + "dialog-overlay"
        NinePatchImageSelector on source {
            states: [
                {"modal": false}
            ]
        }
    }
}
