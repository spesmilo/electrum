// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.Universal
import QtQuick.Dialogs.quickimpl as DialogsQuickImpl

DialogsQuickImpl.FileDialogDelegate {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             implicitIndicatorHeight + topPadding + bottomPadding)

    spacing: 12

    padding: 12
    topPadding: padding - 1
    bottomPadding: padding + 1

    icon.width: 20
    icon.height: 20
    icon.color: Color.transparent(Universal.foreground, enabled ? 1.0 : 0.2)
    icon.source: "qrc:/qt-project.org/imports/QtQuick/Dialogs/quickimpl/images/folder-icon-square.png"

    file: fileUrl

    required property int index
    required property string fileName
    required property url fileUrl
    required property date fileModified

    contentItem: DialogsQuickImpl.FolderDialogDelegateLabel {
        delegate: control
        fileDetailRowTextColor: control.Universal.baseMediumColor
    }

    background: Rectangle {
        visible: control.down || control.highlighted || control.visualFocus || control.hovered
        color: control.down ? control.Universal.listMediumColor :
               control.hovered ? control.Universal.listLowColor : control.Universal.altMediumLowColor

        Rectangle {
            width: parent.width
            height: parent.height
            visible: control.visualFocus || control.highlighted
            color: control.Universal.accent
            opacity: control.Universal.theme === Universal.Light ? 0.4 : 0.6
        }
    }
}
