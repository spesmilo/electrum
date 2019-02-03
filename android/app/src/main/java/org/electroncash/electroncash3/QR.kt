package org.electroncash.electroncash3

import android.support.v4.app.Fragment
import android.widget.ImageView
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatWriter
import com.google.zxing.WriterException
import com.google.zxing.integration.android.IntentIntegrator
import com.journeyapps.barcodescanner.BarcodeEncoder


fun scanQR(fragment: Fragment) {
    IntentIntegrator.forSupportFragment(fragment)
        .setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
        .setPrompt("")
        .setBeepEnabled(false)
        .initiateScan()
}


fun showQR(img: ImageView, text: String) {
    // The layout already provides a margin of about 2 blocks, which is enough for all current
    // scanners (https://qrworld.wordpress.com/2011/08/09/the-quiet-zone/).
    val hints = mapOf(EncodeHintType.MARGIN to 0)

    val resolution = app.resources.getDimensionPixelSize(R.dimen.qr_resolution)
    try {
        val matrix = MultiFormatWriter().encode(
            text, BarcodeFormat.QR_CODE, resolution, resolution, hints)
        img.setImageBitmap(BarcodeEncoder().createBitmap(matrix))
    } catch (e: WriterException) {
        if (e.message == "Data too big") {
            img.setImageDrawable(null)
        } else {
            throw e
        }
    }
}