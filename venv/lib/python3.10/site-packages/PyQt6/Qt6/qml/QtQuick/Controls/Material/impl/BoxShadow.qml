// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.Material
import QtQuick.Controls.Material.impl

/*
   A implementation of CSS's box-shadow, used by ElevationEffect for a Material Design
   elevation shadow effect.
 */
RectangularGlow {
    // The 4 properties from CSS box-shadow, plus the inherited color property
    property int offsetX
    property int offsetY
    property int blurRadius
    property int spreadRadius

    // The strength of the shadow. We have this because RectangularGlow spreads
    // out the shadow thinly, whereas lower elevation levels in Material 3
    // are less spread out and stronger. This is only used for items with fully-rounded
    // corners, like buttons.
    property real strength

    // The source item the shadow is being applied to, used for correctly
    // calculating the corner radious
    property Item source

    property bool fullWidth
    property bool fullHeight

    // qmllint disable unqualified
    // Intentionally duck-typed (QTBUG-94807)
    readonly property real sourceRadius: source && source.radius || 0

    x: (parent.width - width)/2 + offsetX
    y: (parent.height - height)/2 + offsetY

    implicitWidth: source ? source.width : parent.width
    implicitHeight: source ? source.height : parent.height

    width: implicitWidth + 2 * spreadRadius + (fullWidth ? 2 * cornerRadius : 0)
    height: implicitHeight + 2 * spreadRadius + (fullHeight ? 2 * cornerRadius : 0)
    glowRadius: blurRadius/2
    spread: strength

    cornerRadius: blurRadius + sourceRadius
}
