// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Pdf
import QtQuick.Shapes

/*!
    \qmltype PdfPageView
    \inqmlmodule QtQuick.Pdf
    \brief A PDF viewer component to show one page a time.

    PdfPageView provides a PDF viewer component that shows one whole page at a
    time, without scrolling. It supports selecting text and copying it to the
    clipboard, zooming in and out, clicking an internal link to jump to another
    section in the document, rotating the view, and searching for text.

    The implementation is a QML assembly of smaller building blocks that are
    available separately. In case you want to make changes in your own version
    of this component, you can copy the QML, which is installed into the
    \c QtQuick/Pdf/qml module directory, and modify it as needed.

    \sa PdfScrollablePageView, PdfMultiPageView, PdfStyle
*/
Rectangle {
    /*!
        \qmlproperty PdfDocument PdfPageView::document

        A PdfDocument object with a valid \c source URL is required:

        \snippet pdfpageview.qml 0
    */
    required property PdfDocument document

    /*!
        \qmlproperty int PdfPageView::status

        This property holds the \l {QtQuick::Image::status}{rendering status} of
        the \l {currentPage}{current page}.
    */
    property alias status: image.status

    /*!
        \qmlproperty PdfDocument PdfPageView::selectedText

        The selected text.
    */
    property alias selectedText: selection.text

    /*!
        \qmlmethod void PdfPageView::selectAll()

        Selects all the text on the \l {currentPage}{current page}, and makes it
        available as the system \l {QClipboard::Selection}{selection} on systems
        that support that feature.

        \sa copySelectionToClipboard()
    */
    function selectAll() {
        selection.selectAll()
    }

    /*!
        \qmlmethod void PdfPageView::copySelectionToClipboard()

        Copies the selected text (if any) to the
        \l {QClipboard::Clipboard}{system clipboard}.

        \sa selectAll()
    */
    function copySelectionToClipboard() {
        selection.copyToClipboard()
    }

    // --------------------------------
    // page navigation

    /*!
        \qmlproperty int PdfPageView::currentPage
        \readonly

        This property holds the zero-based page number of the page visible in the
        scrollable view. If there is no current page, it holds -1.

        This property is read-only, and is typically used in a binding (or
        \c onCurrentPageChanged script) to update the part of the user interface
        that shows the current page number, such as a \l SpinBox.

        \sa PdfPageNavigator::currentPage
    */
    property alias currentPage: pageNavigator.currentPage

    /*!
        \qmlproperty bool PdfPageView::backEnabled
        \readonly

        This property indicates if it is possible to go back in the navigation
        history to a previous-viewed page.

        \sa PdfPageNavigator::backAvailable, back()
    */
    property alias backEnabled: pageNavigator.backAvailable

    /*!
        \qmlproperty bool PdfPageView::forwardEnabled
        \readonly

        This property indicates if it is possible to go to next location in the
        navigation history.

        \sa PdfPageNavigator::forwardAvailable, forward()
    */
    property alias forwardEnabled: pageNavigator.forwardAvailable

    /*!
        \qmlmethod void PdfPageView::back()

        Scrolls the view back to the previous page that the user visited most
        recently; or does nothing if there is no previous location on the
        navigation stack.

        \sa PdfPageNavigator::back(), currentPage, backEnabled
    */
    function back() { pageNavigator.back() }

    /*!
        \qmlmethod void PdfPageView::forward()

        Scrolls the view to the page that the user was viewing when the back()
        method was called; or does nothing if there is no "next" location on the
        navigation stack.

        \sa PdfPageNavigator::forward(), currentPage
    */
    function forward() { pageNavigator.forward() }

    /*!
        \qmlmethod void PdfPageView::goToPage(int page)

        Changes the view to the \a page, if possible.

        \sa PdfPageNavigator::jump(), currentPage
    */
    function goToPage(page) { goToLocation(page, Qt.point(0, 0), 0) }

    /*!
        \qmlmethod void PdfPageView::goToLocation(int page, point location, real zoom)

        Scrolls the view to the \a location on the \a page, if possible,
        and sets the \a zoom level.

        \sa PdfPageNavigator::jump(), currentPage
    */
    function goToLocation(page, location, zoom) {
        if (zoom > 0)
            root.renderScale = zoom
        pageNavigator.jump(page, location, zoom)
    }

    // --------------------------------
    // page scaling

    /*!
        \qmlproperty bool PdfPageView::zoomEnabled

        This property holds whether the user can use the pinch gesture or
        Control + mouse wheel to zoom. The default is \c true.

        When the user zooms the page, the size of PdfPageView changes.
    */
    property bool zoomEnabled: true

    /*!
        \qmlproperty real PdfPageView::renderScale

        This property holds the ratio of pixels to points. The default is \c 1,
        meaning one point (1/72 of an inch) equals 1 logical pixel.
    */
    property real renderScale: 1

    /*!
        \qmlproperty size PdfPageView::sourceSize

        This property holds the scaled width and height of the full-frame image.

        \sa {QtQuick::Image::sourceSize}{Image.sourceSize}
    */
    property alias sourceSize: image.sourceSize

    /*!
        \qmlmethod void PdfPageView::resetScale()

        Sets \l renderScale back to its default value of \c 1.
    */
    function resetScale() {
        image.sourceSize.width = 0
        image.sourceSize.height = 0
        root.scale = 1
    }

    /*!
        \qmlmethod void PdfPageView::scaleToWidth(real width, real height)

        Sets \l renderScale such that the width of the first page will fit into a
        viewport with the given \a width and \a height. If the page is not rotated,
        it will be scaled so that its width fits \a width. If it is rotated +/- 90
        degrees, it will be scaled so that its width fits \a height.
    */
    function scaleToWidth(width, height) {
        const halfRotation = Math.abs(root.rotation % 180)
        image.sourceSize = Qt.size((halfRotation > 45 && halfRotation < 135) ? height : width, 0)
        image.centerInSize = Qt.size(width, height)
        image.centerOnLoad = true
        image.vCenterOnLoad = (halfRotation > 45 && halfRotation < 135)
        root.scale = 1
    }

    /*!
        \qmlmethod void PdfPageView::scaleToPage(real width, real height)

        Sets \l renderScale such that the whole first page will fit into a viewport
        with the given \a width and \a height. The resulting \l renderScale depends
        on page rotation: the page will fit into the viewport at a larger size if it
        is first rotated to have a matching aspect ratio.
    */
    function scaleToPage(width, height) {
        const windowAspect = width / height
        const halfRotation = Math.abs(root.rotation % 180)
        const pagePointSize = document.pagePointSize(pageNavigator.currentPage)
        const pageAspect = pagePointSize.height / pagePointSize.width
        if (halfRotation > 45 && halfRotation < 135) {
            // rotated 90 or 270º
            if (windowAspect > pageAspect) {
                image.sourceSize = Qt.size(height, 0)
            } else {
                image.sourceSize = Qt.size(0, width)
            }
        } else {
            if (windowAspect > pageAspect) {
                image.sourceSize = Qt.size(0, height)
            } else {
                image.sourceSize = Qt.size(width, 0)
            }
        }
        image.centerInSize = Qt.size(width, height)
        image.centerOnLoad = true
        image.vCenterOnLoad = true
        root.scale = 1
    }

    // --------------------------------
    // text search

    /*!
        \qmlproperty PdfSearchModel PdfPageView::searchModel

        This property holds a PdfSearchModel containing the list of search results
        for a given \l searchString.

        \sa PdfSearchModel
    */
    property alias searchModel: searchModel

    /*!
        \qmlproperty string PdfPageView::searchString

        This property holds the search string that the user may choose to search
        for. It is typically used in a binding to the \c text property of a
        TextField.

        \sa searchModel
    */
    property alias searchString: searchModel.searchString

    /*!
        \qmlmethod void PdfPageView::searchBack()

        Decrements the
        \l{PdfSearchModel::currentResult}{searchModel's current result}
        so that the view will jump to the previous search result.
    */
    function searchBack() { --searchModel.currentResult }

    /*!
        \qmlmethod void PdfPageView::searchForward()

        Increments the
        \l{PdfSearchModel::currentResult}{searchModel's current result}
        so that the view will jump to the next search result.
    */
    function searchForward() { ++searchModel.currentResult }

    // --------------------------------
    // implementation
    id: root
    width: image.width
    height: image.height

    PdfSelection {
        id: selection
        document: root.document
        page: pageNavigator.currentPage
        from: Qt.point(textSelectionDrag.centroid.pressPosition.x / image.pageScale, textSelectionDrag.centroid.pressPosition.y / image.pageScale)
        to: Qt.point(textSelectionDrag.centroid.position.x / image.pageScale, textSelectionDrag.centroid.position.y / image.pageScale)
        hold: !textSelectionDrag.active && !tapHandler.pressed
    }

    PdfSearchModel {
        id: searchModel
        document: root.document === undefined ? null : root.document
        onCurrentPageChanged: root.goToPage(currentPage)
    }

    PdfPageNavigator {
        id: pageNavigator
        onCurrentPageChanged: searchModel.currentPage = currentPage
        onCurrentZoomChanged: root.renderScale = currentZoom

        property url documentSource: root.document.source
        onDocumentSourceChanged: {
            pageNavigator.clear()
            root.goToPage(0)
        }
    }

    PdfPageImage {
        id: image
        document: root.document
        currentFrame: pageNavigator.currentPage
        asynchronous: true
        fillMode: Image.PreserveAspectFit
        property bool centerOnLoad: false
        property bool vCenterOnLoad: false
        property size centerInSize
        property real pageScale: image.paintedWidth / document.pagePointSize(pageNavigator.currentPage).width
        function reRenderIfNecessary() {
            const newSourceWidth = image.sourceSize.width * root.scale * Screen.devicePixelRatio
            const ratio = newSourceWidth / image.sourceSize.width
            if (ratio > 1.1 || ratio < 0.9) {
                image.sourceSize.width = newSourceWidth
                image.sourceSize.height = 0
                root.scale = 1
            }
        }
        onStatusChanged:
            if (status == Image.Ready && centerOnLoad) {
                root.x = (centerInSize.width - image.implicitWidth) / 2
                root.y = vCenterOnLoad ? (centerInSize.height - image.implicitHeight) / 2 : 0
                centerOnLoad = false
                vCenterOnLoad = false
            }
    }
    onRenderScaleChanged: {
        image.sourceSize.width = document.pagePointSize(pageNavigator.currentPage).width * renderScale
        image.sourceSize.height = 0
        root.scale = 1
    }

    Shape {
        anchors.fill: parent
        opacity: 0.25
        visible: image.status === Image.Ready
        ShapePath {
            strokeWidth: 1
            strokeColor: "cyan"
            fillColor: "steelblue"
            scale: Qt.size(image.pageScale, image.pageScale)
            PathMultiline {
                paths: searchModel.currentPageBoundingPolygons
            }
        }
        ShapePath {
            strokeWidth: 1
            strokeColor: "orange"
            fillColor: "cyan"
            scale: Qt.size(image.pageScale, image.pageScale)
            PathMultiline {
                paths: searchModel.currentResultBoundingPolygons
            }
        }
        ShapePath {
            fillColor: "orange"
            scale: Qt.size(image.pageScale, image.pageScale)
            PathMultiline {
                paths: selection.geometry
            }
        }
    }

    Repeater {
        model: PdfLinkModel {
            id: linkModel
            document: root.document
            page: pageNavigator.currentPage
        }
        delegate: PdfLinkDelegate {
            x: rectangle.x * image.pageScale
            y: rectangle.y * image.pageScale
            width: rectangle.width * image.pageScale
            height: rectangle.height * image.pageScale
            visible: image.status === Image.Ready
            onTapped:
                (link) => {
                    if (link.page >= 0)
                        pageNavigator.jump(link)
                    else
                        Qt.openUrlExternally(url)
                }
        }
    }

    PinchHandler {
        id: pinch
        enabled: root.zoomEnabled && root.scale * root.renderScale <= 10 && root.scale * root.renderScale >= 0.1
        minimumScale: 0.1
        maximumScale: 10
        minimumRotation: 0
        maximumRotation: 0
        onActiveChanged: if (!active) image.reRenderIfNecessary()
        grabPermissions: PinchHandler.TakeOverForbidden // don't allow takeover if pinch has started
    }
    WheelHandler {
        enabled: pinch.enabled
        acceptedModifiers: Qt.ControlModifier
        property: "scale"
        onActiveChanged: if (!active) image.reRenderIfNecessary()
    }
    DragHandler {
        id: textSelectionDrag
        acceptedDevices: PointerDevice.Mouse | PointerDevice.Stylus
        target: null
    }
    TapHandler {
        id: tapHandler
        acceptedDevices: PointerDevice.Mouse | PointerDevice.Stylus
    }
}
