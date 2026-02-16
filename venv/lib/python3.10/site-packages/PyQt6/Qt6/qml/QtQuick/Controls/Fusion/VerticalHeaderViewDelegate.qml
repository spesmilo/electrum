// Copyright (C) 2025 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.Fusion as FusionControls

T.HeaderViewDelegate {
    id: control

    // same as AbstractButton.qml
    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    padding: 8

    highlighted: selected

    background: Rectangle {
        id: backgroundRect
        color: control.palette.button
        gradient: Gradient {
            GradientStop {
                position: 0
                color: FusionControls.Fusion.gradientStart(backgroundRect.color)
            }
            GradientStop {
                position: 1
                color: FusionControls.Fusion.gradientStop(backgroundRect.color)
            }
        }
    }

    contentItem: Label {
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        text: control.model[control.headerView.textRole]
    }
}
