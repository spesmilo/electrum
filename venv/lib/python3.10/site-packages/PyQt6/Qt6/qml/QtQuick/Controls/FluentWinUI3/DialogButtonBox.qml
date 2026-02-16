// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Templates as T

T.DialogButtonBox {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    spacing: 8
    padding: 24

    alignment: count === 1 ? Qt.AlignRight : undefined

    delegate: Button {
        highlighted: DialogButtonBox.buttonRole === DialogButtonBox.AcceptRole || DialogButtonBox.buttonRole === DialogButtonBox.YesRole
    }

    contentItem: ListView {
        implicitWidth: contentWidth
        model: control.contentModel
        spacing: control.spacing
        orientation: ListView.Horizontal
        boundsBehavior: Flickable.StopAtBounds
        snapMode: ListView.SnapToItem
    }

    background: Item {
        readonly property bool __isHighContrast: Application.styleHints.accessibility.contrastPreference === Qt.HighContrast
        implicitHeight: 81
        Rectangle {
            implicitHeight: parent.__isHighContrast ? 2 : 1
            width: parent.width
            color: parent.__isHighContrast ? control.palette.text : Application.styleHints.colorScheme === Qt.Light ? "#0F000000" : "#15FFFFFF"
        }
        Rectangle {
            implicitHeight: parent.__isHighContrast ? 79 : 80
            x: 1; y: parent.__isHighContrast ? 2 : 1
            width: parent.width - 2
            height: parent.height - (parent.__isHighContrast ? 3 : 2)
            color: control.palette.window
            topLeftRadius: 0
            bottomLeftRadius: 7
            bottomRightRadius: 7
            topRightRadius: 0
        }
    }
}
