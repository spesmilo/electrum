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

    leftPadding: 20
    rightPadding: 20
    // Ensure that the background's border is visible.
    leftInset: -1
    rightInset: -1
    topInset: -1
    bottomInset: -1

    standardButtons: T.Dialog.Open | T.Dialog.Cancel

    Dialog {
        id: overwriteConfirmationDialog
        objectName: "confirmationDialog"
        anchors.centerIn: parent
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutsideParent
        dim: true
        modal: true
        title: qsTr("Overwrite file?")

        contentItem: ColumnLayout {
            width: overwriteConfirmationDialogLastTextLine.width
            Label {
                text: control.fileName + " already exists."
            }
            Label {
                id: overwriteConfirmationDialogLastTextLine
                text: "Do you want to replace it?"
            }
        }

        footer: DialogButtonBox {
            alignment: Qt.AlignHCenter
            standardButtons: DialogButtonBox.Yes | DialogButtonBox.No
        }
    }

    /*
        We use attached properties because we want to handle logic in C++, and:
        - We can't assume the footer only contains a DialogButtonBox (which would allow us
          to connect up to it in QQuickFileDialogImpl); it also needs to hold a ComboBox
          and therefore the root footer item will be e.g. a layout item instead.
        - We don't want to create our own "FileDialogButtonBox" (in order to be able to handle the logic
          in C++) because we'd need to copy (and hence duplicate code in) DialogButtonBox.qml.
    */
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
                visible: parent.parent.parent?.parent === Overlay.overlay && control.title.length > 0
                horizontalAlignment: Label.AlignHCenter
                elide: Label.ElideRight
                font.bold: true
            }

            DialogsImpl.FolderBreadcrumbBar {
                id: breadcrumbBar
                width: parent.width
                dialog: control

                KeyNavigation.tab: fileDialogListView
            }
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
            focus: true
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

    footer: Rectangle {
        color: control.palette.light
        implicitWidth: gridLayout.implicitWidth
        implicitHeight: gridLayout.implicitHeight + 12

        GridLayout {
            // OK to use IDs here, since users shouldn't be overriding this stuff.
            id: gridLayout
            anchors.fill: parent
            anchors.topMargin: 6
            anchors.bottomMargin: 6
            columnSpacing: 20
            columns: 3

            Label {
                id: fileNameLabel
                text: qsTr("File name")
                visible: false

                Layout.leftMargin: 20
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
                Layout.leftMargin: 20
            }

            ComboBox {
                id: nameFiltersComboBox
                model: control.nameFilters
                verticalPadding: 0

                Layout.fillWidth: true
            }

            DialogButtonBox {
                id: buttonBox
                standardButtons: control.standardButtons
                palette.window: control.palette.light
                spacing: 12
                padding: 0

                Layout.row: 1
                Layout.column: 2
                Layout.rightMargin: 20
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
