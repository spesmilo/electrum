// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls
import QtQuick.Controls.impl
import QtQuick.Dialogs.quickimpl as DialogsQuickImpl

DialogsQuickImpl.FolderBreadcrumbBar {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + (upButton ? upButton.implicitWidth + upButtonSpacing : 0)
                            + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding, upButton.implicitHeight)
    upButtonSpacing: 20
    padding: 1

    background: Rectangle {
        color: control.palette.button
    }
    contentItem: ListView {
        currentIndex: control.currentIndex
        model: control.contentModel
        orientation: ListView.Horizontal
        snapMode: ListView.SnapToItem
        highlightMoveDuration: 0
        interactive: false
        clip: true
    }
    buttonDelegate: Button {
        id: buttonDelegateRoot
        text: folderName
        flat: true

        // The default of 100 is a bit too wide for short directory names.
        Binding {
            target: buttonDelegateRoot.background
            property: "implicitWidth"
            value: 40
        }

        required property int index
        required property string folderName
    }
    separatorDelegate: IconImage {
        id: iconImage
        source: "qrc:/qt-project.org/imports/QtQuick/Dialogs/quickimpl/images/crumb-separator-icon-round.png"
        sourceSize: Qt.size(8, 8)
        width: 8
        height: control.contentItem.height
        color: control.palette.buttonText
        y: (control.height - height) / 2
    }
    upButton: ToolButton {
        x: control.leftPadding
        y: control.topPadding
        icon.source: "qrc:/qt-project.org/imports/QtQuick/Dialogs/quickimpl/images/up-icon-round.png"
        icon.width: 16
        icon.height: 16
        width: height
        focusPolicy: Qt.TabFocus
        Accessible.name: qsTr("Up")
    }
    textField: TextField {
        text: (control.dialog as DialogsQuickImpl.FileDialogImpl)?.selectedFile
            ?? (control.dialog as DialogsQuickImpl.FolderDialogImpl).currentFolder
    }
}
