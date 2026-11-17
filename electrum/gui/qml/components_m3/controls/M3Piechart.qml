import QtQuick

// Pie chart of the Material 3 GUI (balance details): one sector per slice, a legend line and label per sector.
// repeats: components/controls/Piechart.qml:1-76 @ e6df7e1c8 (the API: `slices` = [{ v: fraction, color, text }],
// `innerOffset`, `legendOffset`, `showLegend`; the drawing: sectors from 12 o'clock clockwise, slices of value 0
// skipped, each sector displaced outwards by innerOffset, the legend line and label outside it).
// Differences: the colors of the sectors come from the caller (Material 3 roles, BalanceDetailsPage); the legend
// lines and labels are drawn in `legendColor` (m3.surfaceVariantOn instead of white, readable in both themes) with
// the labelMedium size of the type scale; the chart repaints when the theme or its size changes.
Canvas {
    id: piechart

    property var slices

    property int innerOffset: 10
    property int legendOffset: 8
    property bool showLegend: true
    property color legendColor: m3.surfaceVariantOn

    onSlicesChanged: piechart.requestPaint()
    onLegendColorChanged: piechart.requestPaint()
    onWidthChanged: piechart.requestPaint()
    onHeightChanged: piechart.requestPaint()

    onPaint: {
        var startR = -Math.PI/2

        var ctx = getContext('2d')
        ctx.reset()

        var gap = m3.space8
        ctx.font = "" + m3.textStyle('labelMedium').size + "px '" + app.font.family + "', sans-serif"
        ctx.strokeStyle = piechart.legendColor
        ctx.lineWidth = 2
        var pcx = width/2
        var pcy = height/2
        var radius = height/3

        var endR = startR
        for (const i in slices) {
            var slice = slices[i]
            if (slice.v == 0)
                continue
            startR = endR
            endR = startR + 2*Math.PI*(slice.v)

            // displace origin
            var phi = startR + (endR - startR)/2
            var dx = Math.cos(phi) * innerOffset
            var dy = Math.sin(phi) * innerOffset

            ctx.lineWidth = 2
            ctx.fillStyle = slice.color
            ctx.beginPath()
            ctx.moveTo(pcx+dx, pcy+dy)
            ctx.arc(pcx+dx, pcy+dy, radius, startR, endR, false)
            ctx.lineTo(pcx+dx, pcy+dy)
            ctx.fill()

            if (!showLegend)
                continue

            // displace legend
            var dx = Math.cos(phi) * (radius + innerOffset + legendOffset)
            var dy = Math.sin(phi) * (radius + innerOffset + legendOffset)
            var dx2 = Math.cos(phi) * (radius + innerOffset + 2 * legendOffset)
            var dy2 = Math.sin(phi) * (radius + innerOffset + 2 * legendOffset)
            ctx.lineWidth = 1
            ctx.beginPath()
            if (dx > 0) {
                var ddx = ctx.measureText(slice.text).width + 2 * gap
                var xtext = pcx+dx2 + gap
            } else {
                var ddx = -(ctx.measureText(slice.text).width + 2 * gap)
                var xtext = pcx+dx2+ddx + gap
            }
            ctx.moveTo(pcx+dx, pcy+dy)
            ctx.lineTo(pcx+dx2, pcy+dy2)
            ctx.lineTo(pcx+dx2+ddx, pcy+dy2)
            ctx.moveTo(pcx+dx2, pcy+dy2)

            ctx.fillStyle = piechart.legendColor
            ctx.fillText(slice.text, xtext, pcy+dy2 - m3.space4)
            ctx.stroke()
        }
    }
}
