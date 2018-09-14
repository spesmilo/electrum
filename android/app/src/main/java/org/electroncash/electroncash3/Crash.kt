package org.electroncash.electroncash3

import android.content.Context
import android.text.Html
import android.view.View
import android.widget.TextView
import com.chaquo.python.Python
import org.acra.config.CoreConfiguration
import org.acra.data.CrashReportData
import org.acra.data.StringFormat
import org.acra.dialog.CrashReportDialog
import org.acra.file.CrashReportPersister
import org.acra.interaction.DialogInteraction
import org.acra.sender.HttpSender
import org.acra.sender.ReportSender
import org.acra.sender.ReportSenderFactory
import org.json.JSONObject
import java.io.File


val DIALOG_TEMPLATE =  """
    <p>%s %s</p>            <!-- Message -->
    <p>%s: %s <br> %s</p>   <!-- Exception -->
    <p>%s</p>               <!-- App info -->
""".trimIndent()

val KEYS_IN_TEMPLATE = listOf("id", "exc_string", "stack", "description")

class CrashhubDialog : CrashReportDialog() {
    override fun getMainView(): View {
        return TextView(this).apply {
            val json = reportToJson(CrashReportPersister().load(
                intent.getSerializableExtra(DialogInteraction.EXTRA_REPORT_FILE) as File))
            val appInfo = ArrayList<String> ()
            for (key in json.keys()) {
                if (key !in KEYS_IN_TEMPLATE) {
                    appInfo.add("$key: ${json.getString(key)}")
                }
            }
            setText(Html.fromHtml(String.format(
                DIALOG_TEMPLATE, getString (R.string.something_went), getString(R.string.to_help),
                json.getJSONObject("id").getString("type"), json.getString("exc_string"),
                stackToHtml(json.getString("stack")),
                appInfo.joinToString("<br>"))))
        }
    }

    private fun stackToHtml(stack: String): String {
        return stack.replace("<", "&lt;").replace(">", "&gt").replace("\n", "<br>")
    }
}


class CrashhubSenderFactory : ReportSenderFactory {
    override fun create(context: Context, config: CoreConfiguration): ReportSender {
        // TODO switch to Marcel's server https://crashhub.electroncash.org/crash once
        // it's back online.
        return CrashhubSender(config, "https://crashhubtest.bauerj.eu/crash")
    }
}

/** See https://github.com/bauerj/crashhub. Doing this with a custom ReportSender subclass
 * because I can't see any other way to fully customize the JSON structure.
 *
 * TODO: display the GitHub link if the submission is successful (would require overriding
 * HttpSender.sendWithoutAttachments and BaseHttpRequest.send). */
class CrashhubSender(config: CoreConfiguration, uri: String)
    : HttpSender(config, HttpSender.Method.POST,
                 StringFormat.JSON,  // Will only be used to set the Content-Type.
                 uri) {

    override fun convertToString(report: CrashReportData, format: StringFormat): String {
        return reportToJson(report).toString(4)
    }
}


fun reportToJson(report: CrashReportData): JSONObject {
    val json = JSONObject()
    val id = JSONObject()
    json.put("id", id)

    val stackLines = ArrayList<String>()
    for ((i, line) in report.get("STACK_TRACE").toString().split("\n").withIndex()) {
        if (i == 0) {
            val header = line.split(Regex(": "), 2)
            id.put("type", header[0])
            json.put("exc_string", if (header.size > 1) header[1] else "")
        } else {
            if (i == 1) {
                id.put("file", "")  // TODO split from name
                id.put("name", line.trim())
            }
            if (! (line.startsWith("\t") || line.startsWith("Caused by"))) {
                break  // https://github.com/ACRA/acra/issues/695
            }
            stackLines.add(line)
        }
    }
    json.put("stack", stackLines.joinToString("\n"))

    putJson(json, "app_version") { report.get("APP_VERSION_NAME") }
    putJson(json, "os") {
        val build = report.get("BUILD") as JSONObject
        "Android %s on %s %s (%s)".format(
            report.get("ANDROID_VERSION"), build.getString("MANUFACTURER"),
            build.getString("MODEL"), build.getString("DEVICE"))
    }
    putJson(json, "locale") {
        (report.get("CRASH_CONFIGURATION") as JSONObject).getString("locale")
    }
    putJson(json, "python_version") {
        Python.getInstance().getModule("sys").get("version").toString()
            .replace("\n", " ")  // https://github.com/bauerj/crashhub/issues/8
    }

    // This field is required by the server, but we can't detemine it because ACRA runs in
    // a separate process.
    json.put("wallet_type", "unknown")

    putJson(json, "description") { report.get("USER_COMMENT") }
    return json
}

fun putJson(obj: JSONObject, key: String, getValue: () -> Any) {
    try {
        obj.put(key, getValue())
    } catch (e: Exception) {
        obj.put(key, e.toString())
    }
}
