import { useState, useEffect, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import { revealItemInDir } from "@tauri-apps/plugin-opener";

interface FileInfo {
  size: number;
  name: string;
  mime: string;
  category: string;
  preview_base64: string | null;
  preview_data_url: string | null;
}

interface EncryptFileResult {
  input_size: number;
  output_size: number;
  output_path: string;
}

interface DecryptFileResult {
  size: number;
  mime: string;
  extension: string;
  temp_path: string;
  category: string;
  preview_base64: string | null;
  preview_data_url: string | null;
}

// Unified preview data shape used by both panes
interface PreviewData {
  category: string;
  preview_base64: string | null;
  preview_data_url: string | null;
}

// --- Inline preview renderer ---
function InlinePreview({ data }: { data: PreviewData }) {
  if (!data.preview_data_url || !data.preview_base64) return null;

  const cat = data.category;
  if (cat === "Image")
    return <div className="inline-preview"><img src={data.preview_data_url} alt="" /></div>;
  if (cat === "Video")
    return <div className="inline-preview"><video controls src={data.preview_data_url} /></div>;
  if (cat === "Audio")
    return <div className="inline-preview"><audio controls src={data.preview_data_url} /></div>;
  if (cat === "Pdf")
    return <PdfPreview base64={data.preview_base64} />;
  if (cat === "Text") {
    const text = atob(data.preview_base64);
    return <div className="inline-preview"><pre className="text-preview">{text.slice(0, 100000)}</pre></div>;
  }
  return null;
}

// PDF needs a blob: URL + iframe — embed/data: URIs are blocked by WebView
function PdfPreview({ base64 }: { base64: string }) {
  const blobUrl = useMemo(() => {
    const raw = atob(base64);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    const blob = new Blob([bytes], { type: "application/pdf" });
    return URL.createObjectURL(blob);
  }, [base64]);

  useEffect(() => {
    return () => URL.revokeObjectURL(blobUrl);
  }, [blobUrl]);

  return (
    <div className="inline-preview">
      <iframe src={blobUrl} style={{ width: "100%", height: "100%", border: "none" }} />
    </div>
  );
}

function hasPreview(data: PreviewData | null): boolean {
  return !!data && !!data.preview_base64 && ["Image", "Video", "Audio", "Text", "Pdf"].includes(data.category);
}

export default function Workspace({ uskB64 }: { uskB64: string }) {
  // Left pane
  const [leftPath, setLeftPath] = useState<string | null>(null);
  const [leftName, setLeftName] = useState("");
  const [leftSize, setLeftSize] = useState(0);
  const [leftPreview, setLeftPreview] = useState<PreviewData | null>(null);

  // Right pane
  const [rightPath, setRightPath] = useState<string | null>(null);
  const [rightName, setRightName] = useState("");
  const [rightSize, setRightSize] = useState(0);

  // Decrypt result (for Save button)
  const [decryptResult, setDecryptResult] = useState<DecryptFileResult | null>(null);

  const [dialog, setDialog] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Helper: load file info + preview for left pane
  const loadLeft = async (filePath: string) => {
    try {
      const info: FileInfo = await invoke("get_file_info", { path: filePath });
      setLeftPath(filePath);
      setLeftName(info.name);
      setLeftSize(info.size);
      setLeftPreview({
        category: info.category,
        preview_base64: info.preview_base64,
        preview_data_url: info.preview_data_url,
      });
      setDecryptResult(null);
    } catch (e) {
      console.error("get_file_info failed:", e);
    }
  };

  const loadRight = async (filePath: string) => {
    try {
      const info: FileInfo = await invoke("get_file_info", { path: filePath });
      setRightPath(filePath);
      setRightName(info.name);
      setRightSize(info.size);
    } catch (e) {
      console.error("get_file_info failed:", e);
    }
  };

  // Listen for Tauri native drag-drop events
  useEffect(() => {
    const unlisten = listen<{ paths: string[]; position: { x: number; y: number } }>(
      "tauri://drag-drop",
      async (event) => {
        const paths = event.payload.paths;
        if (!paths || paths.length === 0) return;
        const midX = window.innerWidth / 2;
        if (event.payload.position.x < midX) {
          await loadLeft(paths[0]);
        } else {
          await loadRight(paths[0]);
        }
      }
    );
    return () => { unlisten.then((fn) => fn()); };
  }, []);

  // --- File selection via dialog ---
  const selectLeft = async () => {
    const file = await open({ multiple: false, title: "Select plaintext file" });
    if (file) await loadLeft(file);
  };

  const selectRight = async () => {
    const file = await open({
      multiple: false,
      title: "Select ciphertext file",
      filters: [{ name: "Himitsu Ciphertext", extensions: ["himitsu"] }, { name: "All files", extensions: ["*"] }],
    });
    if (file) await loadRight(file);
  };

  // --- Encrypt (auto-save to temp) ---
  const handleEncrypt = async () => {
    if (!leftPath) return;
    setBusy(true);
    try {
      const result: EncryptFileResult = await invoke("encrypt_file", {
        inputPath: leftPath,
        policy: "Access::Broadcast",
      });
      setRightPath(result.output_path);
      setRightName((leftName || "file") + ".himitsu");
      setRightSize(result.output_size);
    } catch (e: any) {
      setDialog(`Encryption failed:\n${e}`);
    } finally {
      setBusy(false);
    }
  };

  // --- Decrypt ---
  const handleDecrypt = async () => {
    if (!rightPath) return;
    if (!uskB64) {
      setDialog("No decryption key loaded.\nGo to the Receiver tab and import a key first.");
      return;
    }
    setBusy(true);
    try {
      const result: DecryptFileResult = await invoke("decrypt_file", {
        inputPath: rightPath,
      });
      setDecryptResult(result);
      setLeftName("decrypted." + result.extension);
      setLeftSize(result.size);
      setLeftPath(result.temp_path);
      setLeftPreview({
        category: result.category,
        preview_base64: result.preview_base64,
        preview_data_url: result.preview_data_url,
      });
    } catch (e: any) {
      setDialog(`Decryption failed:\n${e}`);
    } finally {
      setBusy(false);
    }
  };

  // --- Save temp file (works for both encrypted and decrypted) ---
  const handleSave = async (tempPath: string, defaultName: string) => {
    const dest = await save({
      title: "Save file",
      defaultPath: defaultName,
    });
    if (!dest) return;
    try {
      await invoke("save_temp_file", { tempPath, destPath: dest });
    } catch (e: any) {
      setDialog(`Save failed:\n${e}`);
    }
  };

  // --- Reveal file in system file manager ---
  const handleReveal = async (path: string) => {
    try {
      await revealItemInDir(path);
    } catch (e) {
      console.error("reveal failed:", e);
    }
  };

  const clearLeft = () => { setLeftPath(null); setLeftName(""); setLeftSize(0); setLeftPreview(null); setDecryptResult(null); };
  const clearRight = () => { setRightPath(null); setRightName(""); setRightSize(0); };

  return (
    <div className="workspace">
      <div className="workspace-panels">
        {/* LEFT: Plaintext */}
        <div className="panel panel-left">
          <div className="panel-label">
            Plaintext
            {leftName && <span className="panel-file-name">{leftName}</span>}
          </div>
          <div
            className={`drop-zone ${leftPath ? "has-content" : ""}`}
            onClick={() => !leftPath && selectLeft()}
          >
            {leftPath ? (
              <>
                <div className="drop-zone-actions">
                  {decryptResult && (
                    <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); handleSave(decryptResult.temp_path, "decrypted." + decryptResult.extension); }}>Save</button>
                  )}
                  <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); handleReveal(leftPath); }}>Reveal</button>
                  <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); clearLeft(); }}>Clear</button>
                </div>
                {hasPreview(leftPreview) ? (
                  <InlinePreview data={leftPreview!} />
                ) : (
                  <div className="binary-info">
                    <div className="binary-size">{formatBytes(leftSize)}</div>
                    <div className="binary-name">{leftName}</div>
                  </div>
                )}
              </>
            ) : (
              <div className="drop-hint">Drop file here<br/>or click to select</div>
            )}
          </div>
        </div>

        {/* RIGHT: Ciphertext */}
        <div className="panel">
          <div className="panel-label">
            Ciphertext
            {rightName && <span className="panel-file-name">{rightName}</span>}
          </div>
          <div
            className={`drop-zone ${rightPath ? "has-content" : ""}`}
            onClick={() => !rightPath && selectRight()}
          >
            {rightPath ? (
              <>
                <div className="drop-zone-actions">
                  <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); handleSave(rightPath, rightName); }}>Save</button>
                  <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); handleReveal(rightPath); }}>Reveal</button>
                  <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); clearRight(); }}>Clear</button>
                </div>
                <div className="binary-info">
                  <div className="binary-size">{rightSize ? formatBytes(rightSize) : ""}</div>
                  <div className="binary-name">{rightName}</div>
                </div>
              </>
            ) : (
              <div className="drop-hint">Drop ciphertext here<br/>or click to select</div>
            )}
          </div>
        </div>
      </div>

      {/* Action bar */}
      <div className="workspace-actions">
        <button className="btn btn-primary" disabled={!leftPath || busy} onClick={handleEncrypt}>
          {busy ? "..." : "Encrypt \u00BB"}
        </button>
        <button className="btn btn-primary" disabled={!rightPath || busy} onClick={handleDecrypt}>
          {busy ? "..." : "\u00AB Decrypt"}
        </button>
      </div>

      {/* Error dialog */}
      {dialog && (
        <div className="dialog-overlay" onClick={() => setDialog(null)}>
          <div className="dialog" onClick={(e) => e.stopPropagation()}>
            <h3>Error</h3>
            <p style={{ whiteSpace: "pre-wrap" }}>{dialog}</p>
            <div className="btn-row" style={{ justifyContent: "flex-end" }}>
              <button className="btn btn-primary" onClick={() => setDialog(null)}>OK</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}
