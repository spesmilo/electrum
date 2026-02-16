// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Material
import QtQuick.Controls.Material.impl

T.TextArea {
    id: control

    implicitWidth: Math.max(contentWidth + leftPadding + rightPadding,
                            implicitBackgroundWidth + leftInset + rightInset,
                            placeholder.implicitWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(contentHeight + topPadding + bottomPadding,
                             implicitBackgroundHeight + topInset + bottomInset)

    // If we're clipped, or we're in a Flickable that's clipped, set our topInset
    // to half the height of the placeholder text to avoid it being clipped.
    topInset: clip || (parent?.parent as Flickable && parent?.parent.clip) ? placeholder.largestHeight / 2 : 0

    leftPadding: Material.textFieldHorizontalPadding
    rightPadding: Material.textFieldHorizontalPadding
    // Need to account for the placeholder text when it's sitting on top.
    topPadding: Material.containerStyle === Material.Filled && placeholderText.length > 0 && (activeFocus || length > 0)
        ? Material.textFieldVerticalPadding + placeholder.largestHeight
        // When the condition above is not met, the text should always sit in the middle
        // of a default-height TextArea, which is just near the top for a higher-than-default one.
        // Account for any topInset as well, otherwise the text will be too close to the background.
        : ((implicitBackgroundHeight - placeholder.largestHeight) / 2) + topInset
    bottomPadding: Material.textFieldVerticalPadding

    color: enabled ? Material.foreground : Material.hintTextColor
    selectionColor: Material.accentColor
    selectedTextColor: Material.primaryHighlightedTextColor
    placeholderTextColor: enabled && activeFocus ? Material.accentColor : Material.hintTextColor

    Material.containerStyle: Material.Outlined

    cursorDelegate: CursorDelegate { }

    FloatingPlaceholderText {
        id: placeholder
        width: control.width - (control.leftPadding + control.rightPadding)
        text: control.placeholderText
        font: control.font
        color: control.placeholderTextColor
        elide: Text.ElideRight
        renderType: control.renderType
        // When the TextArea is in a Flickable, the background is reparented to it
        // so that decorations don't move with the content. We need to do the same.
        // Also allow the background to be set to null; in that case we're just not visible.
        parent: control.background?.parent ?? null

        filled: control.Material.containerStyle === Material.Filled
        verticalPadding: control.Material.textFieldVerticalPadding
        controlHasActiveFocus: control.activeFocus
        controlHasText: control.length > 0
        controlImplicitBackgroundHeight: control.implicitBackgroundHeight
        controlHeight: control.height
        leftPadding: control.leftPadding
        floatingLeftPadding: control.Material.textFieldHorizontalPadding
    }

    background: MaterialTextContainer {
        implicitWidth: 120
        implicitHeight: control.Material.textFieldHeight

        filled: control.Material.containerStyle === Material.Filled
        fillColor: control.Material.textFieldFilledContainerColor
        outlineColor: (enabled && control.hovered) ? control.Material.primaryTextColor : control.Material.hintTextColor
        focusedOutlineColor: control.Material.accentColor
        // When the control's size is set larger than its implicit size, use whatever size is smaller
        // so that the gap isn't too big.
        placeholderTextWidth: Math.min(placeholder.width, placeholder.implicitWidth) * placeholder.scale
        placeholderTextHAlign: control.effectiveHorizontalAlignment
        controlHasActiveFocus: control.activeFocus
        controlHasText: control.length > 0
        placeholderHasText: placeholder.text.length > 0
        horizontalPadding: control.Material.textFieldHorizontalPadding
    }
}
