package org.electroncash.electroncash3

import android.content.Context
import android.view.View
import android.widget.TextView
import org.acra.ACRA
import org.acra.config.CoreConfiguration
import org.acra.config.CoreConfigurationBuilder
import org.acra.data.CrashReportData
import org.acra.data.StringFormat
import org.acra.dialog.CrashReportDialog
import org.acra.file.CrashReportPersister
import org.acra.interaction.DialogInteraction
import org.acra.scheduler.SchedulerStarter
import org.acra.sender.HttpSender
import org.acra.sender.ReportSender
import org.acra.sender.ReportSenderFactory
import org.acra.util.ApplicationStartupProcessor
import org.json.JSONObject
import java.io.File


lateinit var acraConfig: CoreConfiguration

fun initAcra(app: App) {
    // If the user neither approves nor dismisses a report, ACRA will by default show it again
    // the next time the app starts. But its dialog will appear over the SplashActivity, and
    // then be hidden a few seconds later by the MainActivity. The `false` parameter below
    // prevents this; we will call `checkAcra` later once the UI has stabilized.
    acraConfig = CoreConfigurationBuilder(app).build()
    ACRA.init(app, acraConfig, false)
}

fun checkAcra() {
    ApplicationStartupProcessor(app, acraConfig, SchedulerStarter(app, acraConfig))
        .checkReports(true)
}


val DIALOG_TEMPLATE =  ("%s %s\n\n" +       // Message
                        "%s: %s\n%s\n\n" +  // Exception
                        "%s\n")             // App info

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
            setText(String.format(
                DIALOG_TEMPLATE, getString (R.string.something_went), getString(R.string.to_help),
                json.getJSONObject("id").getString("type"), json.getString("exc_string"),
                json.getString("stack"), appInfo.joinToString("\n")))
        }
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
        py.getModule("sys").get("version").toString()
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
