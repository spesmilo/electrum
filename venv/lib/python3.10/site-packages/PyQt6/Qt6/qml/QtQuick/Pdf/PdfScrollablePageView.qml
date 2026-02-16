// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls
import QtQuick.Pdf
import QtQuick.Shapes

/*!
    \qmltype PdfScrollablePageView
    \inqmlmodule QtQuick.Pdf
    \brief A complete PDF viewer component to show one page a time, with scrolling.

    PdfScrollablePageView provides a PDF viewer component that shows one page
    at a time, with scrollbars to move around the page. It also supports
    selecting text and copying it to the clipboard, zooming in and out,
    clicking an internal link to jump to another section in the document,
    rotating the view, and searching for text. The pdfviewer example
    demonstrates how to use these features in an application.

    The implementation is a QML assembly of smaller building blocks that are
    available separately. In case you want to make changes in your own version
    of this component, you can copy the QML, which is installed into the
    \c QtQuick/Pdf/qml module directory, and modify it as needed.

    \sa PdfPageView, PdfMultiPageView, PdfStyle
*/
Flickable {
    /*!
        \qmlproperty PdfDocument PdfScrollablePageView::document

        A PdfDocument object with a valid \c source URL is required:

        \snippet multipageview.qml 0
    */
    required property PdfDocument document

    /*!
        \qmlproperty int PdfScrollablePageView::status

        This property holds the \l {QtQuick::Image::status}{rendering status} of
        the \l {currentPage}{current page}.
    */
    property alias status: image.status

    /*!
        \qmlproperty PdfDocument PdfScrollablePageView::selectedText

        The selected text.
    */
    property alias selectedText: selection.text

    /*!
        \qmlmethod void PdfScrollablePageView::selectAll()

        Selects all the text on the \l {currentPage}{current page}, and makes it
        available as the system \l {QClipboard::Selection}{selection} on systems
        that support that feature.

        \sa copySelectionToClipboard()
    */
    function selectAll() {
        selection.selectAll()
    }

    /*!
        \qmlmethod void PdfScrollablePageView::copySelectionToClipboard()

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
        \qmlproperty int PdfScrollablePageView::currentPage
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
        \qmlproperty bool PdfScrollablePageView::backEnabled
        \readonly

        This property indicates if it is possible to go back in the navigation
        history to a previous-viewed page.

        \sa PdfPageNavigator::backAvailable, back()
    */
    property alias backEnabled: pageNavigator.backAvailable

    /*!
        \qmlproperty bool PdfScrollablePageView::forwardEnabled
        \readonly

        This property indicates if it is possible to go to next location in the
        navigation history.

        \sa PdfPageNavigator::forwardAvailable, forward()
    */
    property alias forwardEnabled: pageNavigator.forwardAvailable

    /*!
        \qmlmethod void PdfScrollablePageView::back()

        Scrolls the view back to the previous page that the user visited most
        recently; or does nothing if there is no previous location on the
        navigation stack.

        \sa PdfPageNavigator::back(), currentPage, backEnabled
    */
    function back() { pageNavigator.back() }

    /*!
        \qmlmethod void PdfScrollablePageView::forward()

        Scrolls the view to the page that the user was viewing when the back()
        method was called; or does nothing if there is no "next" location on the
        navigation stack.

        \sa PdfPageNavigator::forward(), currentPage
    */
    function forward() { pageNavigator.forward() }

    /*!
        \qmlmethod void PdfScrollablePageView::goToPage(int page)

        Changes the view to the \a page, if possible.

        \sa PdfPageNavigator::jump(), currentPage
    */
    function goToPage(page) {
        if (page === pageNavigator.currentPage)
            return
        goToLocation(page, Qt.point(0, 0), 0)
    }

    /*!
        \qmlmethod void PdfScrollablePageView::goToLocation(int page, point location, real zoom)

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
        \qmlproperty real PdfScrollablePageView::renderScale

        This property holds the ratio of pixels to points. The default is \c 1,
        meaning one point (1/72 of an inch) equals 1 logical pixel.
    */
    property real renderScale: 1

    /*!
        \qmlproperty real PdfScrollablePageView::pageRotation

        This property holds the clockwise rotation of the pages.

        The default value is \c 0 degrees (that is, no rotation relative to the
        orientation of the pages as stored in the PDF file).
    */
    property real pageRotation: 0

    /*!
        \qmlproperty size PdfScrollablePageView::sourceSize

        This property holds the scaled width and height of the full-frame image.

        \sa {QtQuick::Image::sourceSize}{Image.sourceSize}
    */
    property alias sourceSize: image.sourceSize

    /*!
        \qmlmethod void PdfScrollablePageView::resetScale()

        Sets \l renderScale back to its default value of \c 1.
    */
    function resetScale() {
        paper.scale = 1
        root.renderScale = 1
    }

    /*!
        \qmlmethod void PdfScrollablePageView::scaleToWidth(real width, real height)

        Sets \l renderScale such that the width of the first page will fit into a
        viewport with the given \a width and \a height. If the page is not rotated,
        it will be scaled so that its width fits \a width. If it is rotated +/- 90
        degrees, it will be scaled so that its width fits \a height.
    */
    function scaleToWidth(width, height) {
        const pagePointSize = document.pagePointSize(pageNavigator.currentPage)
        root.renderScale = root.width / (paper.rot90 ? pagePointSize.height : pagePointSize.width)
        console.log(lcSPV, "scaling", pagePointSize, "to fit", root.width, "rotated?", paper.rot90, "scale", root.renderScale)
        root.contentX = 0
        root.contentY = 0
    }

    /*!
        \qmlmethod void PdfScrollablePageView::scaleToPage(real width, real height)

        Sets \l renderScale such that the whole first page will fit into a viewport
        with the given \a width and \a height. The resulting \l renderScale depends
        on \l pageRotation: the page will fit into the viewport at a larger size if
        it is first rotated to have a matching aspect ratio.
    */
    function scaleToPage(width, height) {
        const pagePointSize = document.pagePointSize(pageNavigator.currentPage)
        root.renderScale = Math.min(
                    root.width / (paper.rot90 ? pagePointSize.height : pagePointSize.width),
                    root.height / (paper.rot90 ? pagePointSize.width : pagePointSize.height) )
        root.contentX = 0
        root.contentY = 0
    }

    // --------------------------------
    // text search

    /*!
        \qmlproperty PdfSearchModel PdfScrollablePageView::searchModel

        This property holds a PdfSearchModel containing the list of search results
        for a given \l searchString.

        \sa PdfSearchModel
    */
    property alias searchModel: searchModel

    /*!
        \qmlproperty string PdfScrollablePageView::searchString

        This property holds the search string that the user may choose to search
        for. It is typically used in a binding to the \c text property of a
        TextField.

        \sa searchModel
    */
    property alias searchString: searchModel.searchString

    /*!
        \qmlmethod void PdfScrollablePageView::searchBack()

        Decrements the
        \l{PdfSearchModel::currentResult}{searchModel's current result}
        so that the view will jump to the previous search result.
    */
    function searchBack() { --searchModel.currentResult }

    /*!
        \qmlmethod void PdfScrollablePageView::searchForward()

        Increments the
        \l{PdfSearchModel::currentResult}{searchModel's current result}
        so that the view will jump to the next search result.
    */
    function searchForward() { ++searchModel.currentResult }

    // --------------------------------
    // implementation
    id: root
    PdfStyle { id: style }
    contentWidth: paper.width
    contentHeight: paper.height
    ScrollBar.vertical: ScrollBar {
        onActiveChanged:
            if (!active ) {
                const currentLocation = Qt.point((root.contentX + root.width / 2) / root.renderScale,
                                                 (root.contentY + root.height / 2) / root.renderScale)
                pageNavigator.update(pageNavigator.currentPage, currentLocation, root.renderScale)
            }
    }
    ScrollBar.horizontal: ScrollBar {
        onActiveChanged:
            if (!active ) {
                const currentLocation = Qt.point((root.contentX + root.width / 2) / root.renderScale,
                                                 (root.contentY + root.height / 2) / root.renderScale)
                pageNavigator.update(pageNavigator.currentPage, currentLocation, root.renderScale)
            }
    }

    onRenderScaleChanged: {
        paper.scale = 1
        const currentLocation = Qt.point((root.contentX + root.width / 2) / root.renderScale,
                                         (root.contentY + root.height / 2) / root.renderScale)
        pageNavigator.update(pageNavigator.currentPage, currentLocation, root.renderScale)
    }

    PdfSearchModel {
        id: searchModel
        document: root.document === undefined ? null : root.document
        onCurrentResultChanged: pageNavigator.jump(currentResultLink)
    }

    PdfPageNavigator {
        id: pageNavigator
        onJumped: function(current) {
            root.renderScale = current.zoom
            const dx = Math.max(0, current.location.x * root.renderScale - root.width / 2) - root.contentX
            const dy = Math.max(0, current.location.y * root.renderScale - root.height / 2) - root.contentY
            // don't jump if location is in the viewport already, i.e. if the "error" between desired and actual contentX/Y is small
            if (Math.abs(dx) > root.width / 3)
                root.contentX += dx
            if (Math.abs(dy) > root.height / 3)
                root.contentY += dy
            console.log(lcSPV, "going to zoom", current.zoom, "loc", current.location,
                        "on page", current.page, "ended up @", root.contentX + ", " + root.contentY)
        }
        onCurrentPageChanged: searchModel.currentPage = currentPage

        property url documentSource: root.document.source
        onDocumentSourceChanged: {
            pageNavigator.clear()
            root.resetScale()
            root.contentX = 0
            root.contentY = 0
        }
    }

    LoggingCategory {
        id: lcSPV
        name: "qt.pdf.singlepageview"
    }

    Rectangle {
        id: paper
        width: rot90 ? image.height : image.width
        height: rot90 ? image.width : image.height
        property real rotationModulus: Math.abs(root.pageRotation % 180)
        property bool rot90: rotationModulus > 45 && rotationModulus < 135
        property real minScale: 0.1
        property real maxScale: 10

        PdfPageImage {
            id: image
            document: root.document
            currentFrame: pageNavigator.currentPage
            asynchronous: true
            fillMode: Image.PreserveAspectFit
            rotation: root.pageRotation
            anchors.centerIn: parent
            property real pageScale: image.paintedWidth / document.pagePointSize(pageNavigator.currentPage).width
            width: document.pagePointSize(pageNavigator.currentPage).width * root.renderScale
            height: document.pagePointSize(pageNavigator.currentPage).height * root.renderScale
            sourceSize.width: width * Screen.devicePixelRatio
            sourceSize.height: 0

            Shape {
                anchors.fill: parent
                visible: image.status === Image.Ready
                ShapePath {
                    strokeWidth: -1
                    fillColor: style.pageSearchResultsColor
                    scale: Qt.size(image.pageScale, image.pageScale)
                    PathMultiline {
                        paths: searchModel.currentPageBoundingPolygons
                    }
                }
                ShapePath {
                    strokeWidth: style.currentSearchResultStrokeWidth
                    strokeColor: style.currentSearchResultStrokeColor
                    fillColor: "transparent"
                    scale: Qt.size(image.pageScale, image.pageScale)
                    PathMultiline {
                        paths: searchModel.currentResultBoundingPolygons
                    }
                }
                ShapePath {
                    fillColor: style.selectionColor
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
                                pageNavigator.jump(link.page, link.location, link.zoom)
                            else
                                Qt.openUrlExternally(url)
                        }
                }
            }
            DragHandler {
                id: textSelectionDrag
                acceptedDevices: PointerDevice.Mouse | PointerDevice.Stylus
                target: null
            }
            TapHandler {
                id: mouseClickHandler
                acceptedDevices: PointerDevice.Mouse | PointerDevice.Stylus
            }
            TapHandler {
                id: touchTapHandler
                acceptedDevices: PointerDevice.TouchScreen
                onTapped: {
                    selection.clear()
                    selection.focus = true
                }
            }
        }

        PdfSelection {
            id: selection
            anchors.fill: parent
            document: root.document
            page: pageNavigator.currentPage
            renderScale: image.pageScale == 0 ? 1.0 : image.pageScale
            from: textSelectionDrag.centroid.pressPosition
            to: textSelectionDrag.centroid.position
            hold: !textSelectionDrag.active && !mouseClickHandler.pressed
            focus: true
        }

        PinchHandler {
            id: pinch
            minimumScale: paper.minScale / root.renderScale
            maximumScale: Math.max(1, paper.maxScale / root.renderScale)
            minimumRotation: 0
            maximumRotation: 0
            onActiveChanged:
                if (!active) {
                    const centroidInPoints = Qt.point(pinch.centroid.position.x / root.renderScale,
                                                      pinch.centroid.position.y / root.renderScale)
                    const centroidInFlickable = root.mapFromItem(paper, pinch.centroid.position.x, pinch.centroid.position.y)
                    const newSourceWidth = image.sourceSize.width * paper.scale
                    const ratio = newSourceWidth / image.sourceSize.width
                    console.log(lcSPV, "pinch ended with centroid", pinch.centroid.position, centroidInPoints, "wrt flickable", centroidInFlickable,
                                "page at", paper.x.toFixed(2), paper.y.toFixed(2),
                                "contentX/Y were", root.contentX.toFixed(2), root.contentY.toFixed(2))
                    if (ratio > 1.1 || ratio < 0.9) {
                        const centroidOnPage = Qt.point(centroidInPoints.x * root.renderScale * ratio, centroidInPoints.y * root.renderScale * ratio)
                        paper.scale = 1
                        paper.x = 0
                        paper.y = 0
                        root.contentX = centroidOnPage.x - centroidInFlickable.x
                        root.contentY = centroidOnPage.y - centroidInFlickable.y
                        root.renderScale *= ratio // onRenderScaleChanged calls pageNavigator.update() so we don't need to here
                        console.log(lcSPV, "contentX/Y adjusted to", root.contentX.toFixed(2), root.contentY.toFixed(2))
                    } else {
                        paper.x = 0
                        paper.y = 0
                    }
                }
            grabPermissions: PointerHandler.CanTakeOverFromAnything
        }
    }
}
