// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls
import QtQuick.Controls.impl
import QtQuick.Dialogs.quickimpl as DialogsQuickImpl

/*
    Most of the elements in here are the same between styles, so we
    have a reusable component for it and provide some properties to enable style-specific tweaks.
*/
Item {
    id: root
    implicitWidth: column.implicitWidth
    implicitHeight: column.implicitHeight

    required property DialogsQuickImpl.FileDialogDelegate delegate
    required property int fileDetailRowWidth

    property color fileDetailRowTextColor

    Column {
        id: column
        y: (parent.height - height) / 2

        Row {
            spacing: root.delegate.spacing

            IconImage {
                id: iconImage
                source: root.delegate.icon.source
                sourceSize: Qt.size(root.delegate.icon.width, root.delegate.icon.height)
                width: root.delegate.icon.width
                height: root.delegate.icon.height
                color: root.delegate.icon.color
                y: (parent.height - height) / 2
            }
            Label {
                text: root.delegate.fileName
                color: root.delegate.icon.color
                y: (parent.height - height) / 2

                Accessible.ignored: true
            }
        }

        Item {
            id: fileDetailRow
            x: iconImage.width + root.delegate.spacing
            width: fileDetailRowWidth - x - root.delegate.leftPadding
            implicitHeight: childrenRect.height

            Label {
                text: {
                    const fileSize = root.delegate.fileSize;
                    return fileSize > Number.MAX_SAFE_INTEGER
                        ? ('>' + locale.formattedDataSize(Number.MAX_SAFE_INTEGER))
                        : locale.formattedDataSize(fileSize);
                }
                font.pixelSize: root.delegate.font.pixelSize * 0.75
                color: root.fileDetailRowTextColor

                Accessible.ignored: true
            }
            Label {
                text: Qt.formatDateTime(root.delegate.fileModified)
                font.pixelSize: root.delegate.font.pixelSize * 0.75
                color: root.fileDetailRowTextColor
                x: parent.width - width

                Accessible.ignored: true
            }
        }
    }
}
