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

FileDialogImpl {
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

    Dialog {
        id: overwriteConfirmationDialog
        objectName: "confirmationDialog"
        anchors.centerIn: parent
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutsideParent
        dim: true
        modal: true
        spacing: 12
        title: qsTr("Overwrite file?")
        width: control.width - control.leftPadding - control.rightPadding

        contentItem: Label {
            text: qsTr("“%1” already exists.\nDo you want to replace it?").arg(control.fileName)
            wrapMode: Text.WordWrap
        }

        footer: DialogButtonBox {
            standardButtons: DialogButtonBox.Yes | DialogButtonBox.No
        }
    }

    FileDialogImpl.buttonBox: buttonBox
    FileDialogImpl.nameFiltersComboBox: nameFiltersComboBox
    FileDialogImpl.fileDialogListView: fileDialogListView
    FileDialogImpl.breadcrumbBar: breadcrumbBar
    FileDialogImpl.fileNameLabel: fileNameLabel
    FileDialogImpl.fileNameTextField: fileNameTextField
    FileDialogImpl.overwriteConfirmationDialog: overwriteConfirmationDialog
    FileDialogImpl.sideBar: sideBar

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

            Layout.topMargin: parent.parent?.parent !== Overlay.overlay ? 12 : 6
            Layout.leftMargin: 16
            Layout.rightMargin: 16
            Layout.fillWidth: true
            Layout.maximumWidth: parent.width - 28
        }
    }

    contentItem: SplitView {
        id: contentLayout

        contentHeight: sideBar.implicitHeight
        DialogsImpl.SideBar {
            id: sideBar
            dialog: control
            SplitView.minimumWidth: 50
            SplitView.maximumWidth: contentLayout.width / 2
        }

        ListView {
            id: fileDialogListView
            objectName: "fileDialogListView"
            SplitView.fillWidth: true
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            ScrollBar.vertical: ScrollBar {}

            model: FolderListModel {
                folder: control.currentFolder
                nameFilters: control.selectedNameFilter.globs
                showDirsFirst: PlatformTheme.themeHint(PlatformTheme.ShowDirectoriesFirst)
                sortCaseSensitive: false
            }
            delegate: DialogsImpl.FileDialogDelegate {
                objectName: "fileDialogDelegate" + index
                width: ListView.view.width
                highlighted: ListView.isCurrentItem
                dialog: control
                fileDetailRowWidth: nameFiltersComboBox.width

                KeyNavigation.backtab: breadcrumbBar
                KeyNavigation.tab: fileNameTextField.visible ? fileNameTextField : nameFiltersComboBox
            }
        }
    }

    footer: GridLayout {
        columnSpacing: 20
        columns: 3

        Label {
            id: fileNameLabel
            text: qsTr("File name")
            visible: false

            Layout.leftMargin: 16
        }

        TextField {
            id: fileNameTextField
            objectName: "fileNameTextField"
            visible: false

            Layout.fillWidth: true
        }

        Label {
            text: qsTr("Filter")

            Layout.column: 0
            Layout.row: 1
            Layout.leftMargin: 16
            Layout.bottomMargin: 16
        }

        ComboBox {
            id: nameFiltersComboBox
            model: control.nameFilters

            Layout.fillWidth: true
            Layout.bottomMargin: 16
        }

        DialogButtonBox {
            id: buttonBox
            standardButtons: control.standardButtons
            spacing: 12

            Layout.row: 1
            Layout.column: 2
            Layout.columnSpan: 1
            Layout.bottomMargin: 16
            Layout.rightMargin: 16
        }
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
