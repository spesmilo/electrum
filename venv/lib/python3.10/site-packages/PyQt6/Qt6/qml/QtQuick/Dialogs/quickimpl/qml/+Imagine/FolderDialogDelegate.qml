// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick.Controls
import QtQuick.Controls.Imagine
import QtQuick.Controls.Imagine.impl
import QtQuick.Controls.impl as ControlsImpl
import QtQuick.Dialogs.quickimpl as DialogsQuickImpl

DialogsQuickImpl.FileDialogDelegate {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             implicitIndicatorHeight + topPadding + bottomPadding)

    spacing: 12

    topPadding: background ? background.topPadding : 0
    leftPadding: background ? background.leftPadding : 0
    rightPadding: background ? background.rightPadding : 0
    bottomPadding: background ? background.bottomPadding : 0

    topInset: background ? -background.topInset || 0 : 0
    leftInset: background ? -background.leftInset || 0 : 0
    rightInset: background ? -background.rightInset || 0 : 0
    bottomInset: background ? -background.bottomInset || 0 : 0

    file: fileUrl

    icon.width: 16
    icon.height: 16
    icon.color: highlighted ? palette.highlightedText : palette.text
    icon.source: "qrc:/qt-project.org/imports/QtQuick/Dialogs/quickimpl/images/folder-icon-round.png"

    required property int index
    required property string fileName
    required property url fileUrl
    required property date fileModified

    contentItem: DialogsQuickImpl.FolderDialogDelegateLabel {
        delegate: control
        fileDetailRowTextColor: Qt.lighter(control.icon.color)
    }

    background: NinePatchImage {
        source: "qrc:/qt-project.org/imports/QtQuick/Dialogs/quickimpl/images/imagine/filedialogdelegate-background"
        NinePatchImageSelector on source {
            states: [
                { "disabled": !control.enabled },
                { "pressed": control.down },
                { "focused": control.visualFocus },
                { "highlighted": control.highlighted },
                { "mirrored": control.mirrored },
                { "hovered": control.enabled && control.hovered }
            ]
        }
    }
}
