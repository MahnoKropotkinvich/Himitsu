package com.haswell.himitsu

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import androidx.activity.enableEdgeToEdge
import org.json.JSONArray
import org.json.JSONObject

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    // Handle the intent that launched the activity
    handleShareIntent(intent)
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    handleShareIntent(intent)
  }

  private fun handleShareIntent(intent: Intent?) {
    if (intent == null) return
    when (intent.action) {
      Intent.ACTION_SEND -> handleSingleShare(intent)
      Intent.ACTION_SEND_MULTIPLE -> handleMultipleShare(intent)
    }
  }

  private fun handleSingleShare(intent: Intent) {
    val uri = intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
    if (uri != null) {
      val files = JSONArray()
      readUriToJson(uri)?.let { files.put(it) }
      if (files.length() > 0) {
        emitToWebView("share-received", files.toString())
      }
    }
  }

  private fun handleMultipleShare(intent: Intent) {
    val uris = intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)
    if (uris != null && uris.isNotEmpty()) {
      val files = JSONArray()
      for (u in uris) {
        readUriToJson(u)?.let { files.put(it) }
      }
      if (files.length() > 0) {
        emitToWebView("share-received", files.toString())
      }
    }
  }

  /**
   * Read a content:// URI into a JSON object with:
   *   { name: String, size: Int, dataBase64: String }
   */
  private fun readUriToJson(uri: Uri): JSONObject? {
    return try {
      val name = getFileName(uri) ?: "shared_file"
      val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: return null
      val b64 = Base64.encodeToString(bytes, Base64.NO_WRAP)
      JSONObject().apply {
        put("name", name)
        put("size", bytes.size)
        put("dataBase64", b64)
      }
    } catch (e: Exception) {
      android.util.Log.e("Himitsu", "Failed to read shared URI: $uri", e)
      null
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

  /**
   * Emit an event to the Tauri WebView via JavaScript.
   * We post to the WebView with a small delay to ensure it's loaded.
   */
  private fun emitToWebView(event: String, payload: String) {
    // Escape the payload for JavaScript string embedding
    val escaped = payload
      .replace("\\", "\\\\")
      .replace("\"", "\\\"")
      .replace("\n", "\\n")
      .replace("\r", "\\r")

    val js = """
      (function() {
        if (window.__TAURI__) {
          window.__TAURI__.event.emit('$event', $payload);
        } else {
          // Retry after WebView loads
          document.addEventListener('DOMContentLoaded', function() {
            setTimeout(function() {
              if (window.__TAURI__) {
                window.__TAURI__.event.emit('$event', $payload);
              }
            }, 500);
          });
        }
      })();
    """.trimIndent()

    // Use a handler to delay execution until WebView is ready
    android.os.Handler(mainLooper).postDelayed({
      try {
        // Access the WebView via the WryActivity's webView field
        val webViewField = this::class.java.superclass?.superclass?.getDeclaredField("webView")
        webViewField?.isAccessible = true
        val webView = webViewField?.get(this) as? android.webkit.WebView
        webView?.evaluateJavascript(js, null)
          ?: android.util.Log.w("Himitsu", "WebView not available yet")
      } catch (e: Exception) {
        android.util.Log.e("Himitsu", "Failed to emit to WebView", e)
      }
    }, 1000) // 1 second delay to ensure WebView is loaded
  }
}
