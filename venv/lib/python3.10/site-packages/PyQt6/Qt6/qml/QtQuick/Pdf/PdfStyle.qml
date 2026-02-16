// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
import QtQuick

/*!
    \qmltype PdfStyle
    \inqmlmodule QtQuick.Pdf
    \brief A styling interface for the PDF viewer components.

    PdfStyle provides properties to modify the appearance of PdfMultiPageView,
    PdfScrollablePageView, and PdfPageView.

    Default styles are provided to match the
    \l {Styling Qt Quick Controls}{styles in Qt Quick Controls}.
    \l {Using File Selectors with Qt Quick Controls}{File selectors}
    are used to load the PDF style corresponding to the Controls style in use.
    Custom styles are possible, using different \l {QFileSelector}{file selectors}.
*/
QtObject {
    /*! \internal
        \qmlproperty SystemPalette PdfStyle::palette
    */
    property SystemPalette palette: SystemPalette { }

    /*! \internal
        \qmlmethod color PdfStyle::withAlpha()
    */
    function withAlpha(color, alpha) {
        return Qt.hsla(color.hslHue, color.hslSaturation, color.hslLightness, alpha)
    }

    /*!
        \qmlproperty color PdfStyle::selectionColor

        The color of translucent rectangles that are overlaid on
        \l {PdfMultiPageView::selectedText}{selected text}.

        \sa PdfSelection
    */
    property color selectionColor: withAlpha(palette.highlight, 0.5)

    /*!
        \qmlproperty color PdfStyle::pageSearchResultsColor

        The color of translucent rectangles that are overlaid on text that
        matches the \l {PdfMultiPageView::searchString}{search string}.

        \sa PdfSearchModel
    */
    property color pageSearchResultsColor: "#80B0C4DE"

    /*!
        \qmlproperty color PdfStyle::currentSearchResultStrokeColor

        The color of the box outline around the
        \l {PdfSearchModel::currentResult}{current search result}.

        \sa PdfMultiPageView::searchBack(), PdfMultiPageView::searchForward(), PdfSearchModel::currentResult
    */
    property color currentSearchResultStrokeColor: "cyan"

    /*!
        \qmlproperty real PdfStyle::currentSearchResultStrokeWidth

        The line width of the box outline around the
        \l {PdfSearchModel::currentResult}{current search result}.

        \sa PdfMultiPageView::searchBack(), PdfMultiPageView::searchForward(), PdfSearchModel::currentResult
    */
    property real currentSearchResultStrokeWidth: 2
}
