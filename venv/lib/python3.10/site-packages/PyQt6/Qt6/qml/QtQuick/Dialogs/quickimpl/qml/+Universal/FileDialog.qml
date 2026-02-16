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

FileDialogImpl {
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

    Dialog {
        id: overwriteConfirmationDialog
        objectName: "confirmationDialog"
        anchors.centerIn: parent
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutsideParent
        dim: true
        modal: true
        title: qsTr("Overwrite file?")
        width: contentItem.implicitWidth + leftPadding + rightPadding

        contentItem: Label {
            text: qsTr("“%1” already exists.\nDo you want to replace it?").arg(control.fileName)
        }

        footer: DialogButtonBox {
            standardButtons: DialogButtonBox.Yes | DialogButtonBox.No
        }

        Overlay.modal: Rectangle {
            color: overwriteConfirmationDialog.Universal.baseMediumColor
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
                x: 1; y: 1 // // FlyoutBorderThemeThickness
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
            Layout.fillWidth: true
            Layout.maximumWidth: parent.width - 48
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
        columnSpacing: 24
        columns: 3

        Label {
            id: fileNameLabel
            text: qsTr("File name")
            visible: false

            Layout.leftMargin: 24
        }

        TextField {
            id: fileNameTextField
            objectName: "fileNameTextField"
            visible: false

            Layout.fillWidth: true
        }

        Label {
            text: qsTr("Filter")

            Layout.row: 1
            Layout.column: 0
            Layout.leftMargin: 24
            Layout.bottomMargin: 24
        }

        ComboBox {
            id: nameFiltersComboBox
            model: control.nameFilters

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

    T.Overlay.modal: Rectangle {
        color: control.Universal.baseLowColor
    }

    T.Overlay.modeless: Rectangle {
        color: control.Universal.baseLowColor
    }
}
