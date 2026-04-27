package com.haswell.himitsu

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.core.content.FileProvider
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class MainActivity : TauriActivity() {
  private var webViewRef: WebView? = null
  private val pendingShares = mutableListOf<String>()

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    handleShareIntent(intent)
  }

  override fun onWebViewCreate(webView: WebView) {
    webViewRef = webView
    webView.addJavascriptInterface(HimitsuBridge(), "HimitsuBridge")
    flushPendingShares()
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    setIntent(intent)
    handleShareIntent(intent)
  }

  // ---- Receive shares from other apps ----

  private fun handleShareIntent(intent: Intent?) {
    if (intent == null) return
    when (intent.action) {
      Intent.ACTION_SEND -> handleSingleShare(intent)
      Intent.ACTION_SEND_MULTIPLE -> handleMultipleShare(intent)
      Intent.ACTION_VIEW -> handleView(intent)
    }
  }

  private fun handleSingleShare(intent: Intent) {
    val uri = intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
    if (uri != null) {
      val files = JSONArray()
      readUriToJson(uri)?.let { files.put(it) }
      if (files.length() > 0) emitToWebView("share-received", files.toString())
      return
    }

    val text = intent.getStringExtra(Intent.EXTRA_TEXT)
    if (!text.isNullOrEmpty()) {
      val files = JSONArray()
      files.put(textToJson(text))
      emitToWebView("share-received", files.toString())
    }
  }

  private fun handleMultipleShare(intent: Intent) {
    val uris = intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)
    if (uris != null && uris.isNotEmpty()) {
      val files = JSONArray()
      for (u in uris) { readUriToJson(u)?.let { files.put(it) } }
      if (files.length() > 0) emitToWebView("share-received", files.toString())
    }
  }

  private fun handleView(intent: Intent) {
    val uri = intent.data
    if (uri != null) {
      val files = JSONArray()
      readUriToJson(uri)?.let { files.put(it) }
      if (files.length() > 0) emitToWebView("share-received", files.toString())
    }
  }

  private fun readUriToJson(uri: Uri): JSONObject? {
    return try {
      val name = getFileName(uri) ?: "shared_file"
      val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: return null
      val b64 = Base64.encodeToString(bytes, Base64.NO_WRAP)
      JSONObject().apply {
        put("name", name)
        put("size", bytes.size)
        put("dataBase64", b64)
        put("mimeType", contentResolver.getType(uri) ?: "application/octet-stream")
      }
    } catch (e: Exception) {
      android.util.Log.e("Himitsu", "Failed to read shared URI: $uri", e)
      null
    }
  }

  private fun textToJson(text: String): JSONObject {
    val bytes = text.toByteArray(Charsets.UTF_8)
    return JSONObject().apply {
      put("name", "shared.txt")
      put("size", bytes.size)
      put("dataBase64", Base64.encodeToString(bytes, Base64.NO_WRAP))
      put("mimeType", "text/plain")
    }
  }

  private fun getFileName(uri: Uri): String? {
    if (uri.scheme == "content") {
      val cursor = contentResolver.query(uri, null, null, null, null)
      cursor?.use {
        if (it.moveToFirst()) {
          val idx = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
          if (idx >= 0) return it.getString(idx)
        }
      }
    }
    return uri.lastPathSegment
  }

  // ---- Emit events to WebView ----

  private fun emitToWebView(event: String, payload: String) {
    val js = """
      (function() {
        window.__HIMITSU_PENDING_SHARES = window.__HIMITSU_PENDING_SHARES || [];
        window.__HIMITSU_PENDING_SHARES.push.apply(window.__HIMITSU_PENDING_SHARES, $payload);
        window.dispatchEvent(new CustomEvent('$event', { detail: $payload }));
      })();
    """.trimIndent()

    android.os.Handler(mainLooper).postDelayed({
      try {
        val webView = webViewRef
        if (webView != null) {
          webView.evaluateJavascript(js, null)
        } else {
          pendingShares.add(js)
          android.util.Log.w("Himitsu", "WebView not available yet; queued share event")
        }
      } catch (e: Exception) {
        android.util.Log.e("Himitsu", "Failed to emit to WebView", e)
      }
    }, 1000)
  }

  private fun flushPendingShares() {
    android.os.Handler(mainLooper).postDelayed({
      val webView = webViewRef ?: return@postDelayed
      val queued = pendingShares.toList()
      pendingShares.clear()
      for (js in queued) {
        webView.evaluateJavascript(js, null)
      }
    }, 1000)
  }

  // ---- JS interface: all data passed as base64, no file paths ----

  inner class HimitsuBridge {
    /**
     * Share data to other apps via system share sheet.
     * @param dataBase64 file content as base64 string
     * @param filename  display filename (e.g. "photo.jpg")
     * @param mimeType  MIME type (e.g. "application/octet-stream")
     */
    @JavascriptInterface
    fun shareBase64(dataBase64: String, filename: String, mimeType: String) {
      runOnUiThread {
        try {
          val bytes = Base64.decode(dataBase64, Base64.DEFAULT)
          val cacheDir = File(cacheDir, "himitsu_share")
          cacheDir.mkdirs()
          val outFile = File(cacheDir, filename)
          outFile.writeBytes(bytes)

          val uri = FileProvider.getUriForFile(
            this@MainActivity,
            "${applicationContext.packageName}.fileprovider",
            outFile
          )
          val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = mimeType
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
          }
          startActivity(Intent.createChooser(shareIntent, "Share"))
        } catch (e: Exception) {
          android.util.Log.e("Himitsu", "shareBase64 failed", e)
        }
      }
    }
  }
}
