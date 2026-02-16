// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
import QtQuick
import QtQuick.Controls

/*!
    \qmltype PdfLinkDelegate
    \inqmlmodule QtQuick.Pdf
    \brief A component to decorate hyperlinks on a PDF page.

    PdfLinkDelegate provides the component that QML-based PDF viewers
    instantiate on top of each hyperlink that is found on each PDF page.

    This component does not provide any visual decoration, because often the
    hyperlinks will already be formatted in a distinctive way; but when the
    mouse cursor hovers, it changes to Qt::PointingHandCursor, and a tooltip
    appears after a delay. Clicking emits the goToLocation() signal if the link
    is internal, or calls Qt.openUrlExternally() if the link contains a URL.

    \sa PdfPageView, PdfScrollablePageView, PdfMultiPageView
*/
Item {
    id: root
    required property var link
    required property rect rectangle
    required property url url
    required property int page
    required property point location
    required property real zoom

    /*!
        \qmlsignal PdfLinkDelegate::tapped(link)

        Emitted on mouse click or touch tap. The \a link argument is an
        instance of QPdfLink with information about the hyperlink.
    */
    signal tapped(var link)

    /*!
        \qmlsignal PdfLinkDelegate::contextMenuRequested(link)

        Emitted on mouse right-click or touch long-press. The \a link argument
        is an instance of QPdfLink with information about the hyperlink.
    */
    signal contextMenuRequested(var link)

    HoverHandler {
        id: linkHH
        cursorShape: Qt.PointingHandCursor
    }
    TapHandler {
        gesturePolicy: TapHandler.ReleaseWithinBounds
        onTapped: root.tapped(root.link)
    }
    TapHandler {
        acceptedDevices: PointerDevice.Mouse | PointerDevice.TouchPad | PointerDevice.Stylus
        acceptedButtons: Qt.RightButton
        gesturePolicy: TapHandler.ReleaseWithinBounds
        onTapped: root.contextMenuRequested(root.link)
    }
    TapHandler {
        acceptedDevices: PointerDevice.TouchScreen
        onLongPressed: root.contextMenuRequested(root.link)
    }
    ToolTip {
        visible: linkHH.hovered
        delay: 1000
        property string destFormat: qsTr("Page %1 location %2, %3 zoom %4")
        text: root.page >= 0 ?
                  destFormat.arg(root.page + 1).arg(root.location.x.toFixed(1))
                            .arg(root.location.y.toFixed(1)).arg(root.zoom) :
                  root.url
    }
}
