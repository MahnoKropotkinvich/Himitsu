import { useState, useEffect, useMemo, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import { revealItemInDir } from "@tauri-apps/plugin-opener";

interface FileInfo {
  size: number;
  name: string;
  mime: string;
  category: string;
  is_dir: boolean;
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
  original_name: string | null;
}

interface DecryptResult {
  success: boolean;
  size_bytes: number;
  render: {
    kind: string;
    mime?: string;
    extension?: string;
    data_base64?: string;
    data_url?: string;
    category?: string;
    temp_path?: string;
    size_bytes?: number;
    hex_preview?: string;
  };
  message: string;
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

// --- Helpers ---

function arrayBufferToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function guessCategoryFromMime(mime: string): string {
  if (mime.startsWith("image/")) return "Image";
  if (mime.startsWith("video/")) return "Video";
  if (mime.startsWith("audio/")) return "Audio";
  if (mime === "application/pdf") return "Pdf";
  if (mime.startsWith("text/") || mime === "application/json") return "Text";
  return "Binary";
}

export default function Workspace() {
  // Left pane — can hold a file path OR in-memory data (from browser drop)
  const [leftPath, setLeftPath] = useState<string | null>(null);
  const [leftData, setLeftData] = useState<string | null>(null); // base64
  const [leftName, setLeftName] = useState("");
  const [leftSize, setLeftSize] = useState(0);
  const [leftIsDir, setLeftIsDir] = useState(false);
  const [leftPreview, setLeftPreview] = useState<PreviewData | null>(null);

  // Right pane — can hold a file path OR in-memory data
  const [rightPath, setRightPath] = useState<string | null>(null);
  const [rightData, setRightData] = useState<string | null>(null); // base64
  const [rightName, setRightName] = useState("");
  const [rightSize, setRightSize] = useState(0);

  // Decrypt result (for Save button)
  const [decryptResult, setDecryptResult] = useState<DecryptFileResult | null>(null);

  const [dialog, setDialog] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Drag-over visual state
  const [leftDragOver, setLeftDragOver] = useState(false);
  const [rightDragOver, setRightDragOver] = useState(false);

  // Guard against double-firing (Tauri native + HTML5 for same drop)
  const nativeDropTime = useRef(0);

  // Helper: load file info + preview for left pane (from disk path)
  const loadLeft = useCallback(async (filePath: string) => {
    try {
      const info: FileInfo = await invoke("get_file_info", { path: filePath });
      setLeftPath(filePath);
      setLeftData(null);
      setLeftName(info.name);
      setLeftSize(info.size);
      setLeftIsDir(info.is_dir);
      setLeftPreview({
        category: info.category,
        preview_base64: info.preview_base64,
        preview_data_url: info.preview_data_url,
      });
      setDecryptResult(null);
    } catch (e) {
      console.error("get_file_info failed:", e);
    }
  }, []);

  const loadRight = useCallback(async (filePath: string) => {
    try {
      const info: FileInfo = await invoke("get_file_info", { path: filePath });
      setRightPath(filePath);
      setRightData(null);
      setRightName(info.name);
      setRightSize(info.size);
    } catch (e) {
      console.error("get_file_info failed:", e);
    }
  }, []);

  // Load in-memory data into left pane (from browser drop)
  const loadLeftFromMemory = useCallback((name: string, size: number, mime: string, base64: string) => {
    const category = guessCategoryFromMime(mime);
    const dataUrl = `data:${mime};base64,${base64}`;
    setLeftPath(null);
    setLeftData(base64);
    setLeftName(name);
    setLeftSize(size);
    setLeftIsDir(false);
    setLeftPreview({
      category,
      preview_base64: base64,
      preview_data_url: dataUrl,
    });
    setDecryptResult(null);
  }, []);

  // Load in-memory data into right pane (from browser drop)
  const loadRightFromMemory = useCallback((name: string, size: number, base64: string) => {
    setRightPath(null);
    setRightData(base64);
    setRightName(name);
    setRightSize(size);
  }, []);

  // --- Tauri native drag-drop ---
  useEffect(() => {
    const unlisten = listen<{ paths: string[]; position: { x: number; y: number } }>(
      "tauri://drag-drop",
      async (event) => {
        const paths = event.payload.paths;
        if (!paths || paths.length === 0) return;
        nativeDropTime.current = Date.now();
        const midX = window.innerWidth / 2;
        if (event.payload.position.x < midX) {
          await loadLeft(paths[0]);
        } else {
          await loadRight(paths[0]);
        }
      }
    );
    return () => { unlisten.then((fn) => fn()); };
  }, [loadLeft, loadRight]);

  // --- HTML5 drag-drop (for browser-dragged content) ---
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDropLeft = useCallback(async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setLeftDragOver(false);

    // Skip if Tauri native just fired (within 500ms)
    if (Date.now() - nativeDropTime.current < 500) return;

    const files = e.dataTransfer.files;
    if (!files || files.length === 0) return;

    const file = files[0];
    const buf = await file.arrayBuffer();
    const base64 = arrayBufferToBase64(buf);
    loadLeftFromMemory(file.name, file.size, file.type || "application/octet-stream", base64);
  }, [loadLeftFromMemory]);

  const handleDropRight = useCallback(async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setRightDragOver(false);

    if (Date.now() - nativeDropTime.current < 500) return;

    const files = e.dataTransfer.files;
    if (!files || files.length === 0) return;

    const file = files[0];
    const buf = await file.arrayBuffer();
    const base64 = arrayBufferToBase64(buf);
    loadRightFromMemory(file.name, file.size, base64);
  }, [loadRightFromMemory]);

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

  // --- Encrypt ---
  const handleEncrypt = async () => {
    if (!leftPath && !leftData) return;
    setBusy(true);
    try {
      let result: EncryptFileResult;
      if (leftData) {
        // In-memory content (browser drag)
        result = await invoke("encrypt_content", {
          dataBase64: leftData,
          filename: leftName || "dropped",
        });
      } else {
        // Disk file
        const cmd = leftIsDir ? "encrypt_folder" : "encrypt_file";
        result = await invoke(cmd, { inputPath: leftPath });
      }
      setRightPath(result.output_path);
      setRightData(null);
      setRightName(result.output_path.split(/[/\\]/).pop() || "encrypted.himitsu");
      setRightSize(result.output_size);
    } catch (e: any) {
      setDialog(`Encryption failed:\n${e}`);
    } finally {
      setBusy(false);
    }
  };

  // --- Decrypt ---
  const handleDecrypt = async () => {
    if (!rightPath && !rightData) return;
    setBusy(true);
    try {
      if (rightData) {
        // In-memory ciphertext (browser drag)
        const result: DecryptResult = await invoke("decrypt_content", {
          ciphertextBase64: rightData,
        });
        const r = result.render;
        const name = r.extension ? `decrypted.${r.extension}` : "decrypted";
        setLeftPath(null);
        setLeftData(r.data_base64 || null);
        setLeftName(name);
        setLeftSize(result.size_bytes);
        setLeftIsDir(false);
        setLeftPreview({
          category: r.category ? String(r.category) : "Binary",
          preview_base64: r.data_base64 || null,
          preview_data_url: r.data_url || null,
        });
        setDecryptResult(null); // no temp file to save
      } else {
        // Disk file
        const result: DecryptFileResult = await invoke("decrypt_file", {
          inputPath: rightPath,
        });
        setDecryptResult(result);
        const isFolder = result.category === "Folder";
        const displayName = result.original_name
          || (isFolder ? result.temp_path.split(/[/\\]/).pop() || "folder" : "decrypted." + result.extension);
        setLeftName(displayName);
        setLeftSize(result.size);
        setLeftIsDir(isFolder);
        setLeftPath(result.temp_path);
        setLeftData(null);
        setLeftPreview({
          category: result.category,
          preview_base64: result.preview_base64,
          preview_data_url: result.preview_data_url,
        });
      }
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

  const clearLeft = () => { setLeftPath(null); setLeftData(null); setLeftName(""); setLeftSize(0); setLeftIsDir(false); setLeftPreview(null); setDecryptResult(null); };
  const clearRight = () => { setRightPath(null); setRightData(null); setRightName(""); setRightSize(0); };

  const leftHasContent = leftPath || leftData;
  const rightHasContent = rightPath || rightData;

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
            className={`drop-zone ${leftHasContent ? "has-content" : ""} ${leftDragOver ? "drag-over" : ""}`}
            onClick={() => !leftHasContent && selectLeft()}
            onDragOver={handleDragOver}
            onDragEnter={(e) => { e.preventDefault(); setLeftDragOver(true); }}
            onDragLeave={() => setLeftDragOver(false)}
            onDrop={handleDropLeft}
          >
            {leftHasContent ? (
              <>
                <div className="drop-zone-actions">
                  {decryptResult && (
                    <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); handleSave(decryptResult.temp_path, decryptResult.original_name || ("decrypted." + decryptResult.extension)); }}>Save</button>
                  )}
                  {leftPath && (
                    <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); handleReveal(leftPath); }}>Reveal</button>
                  )}
                  <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); clearLeft(); }}>Clear</button>
                </div>
                {hasPreview(leftPreview) ? (
                  <InlinePreview data={leftPreview!} />
                ) : (
                  <div className="binary-info">
                    <div className="binary-size">{leftIsDir ? "Folder" : ""} {formatBytes(leftSize)}</div>
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
            className={`drop-zone ${rightHasContent ? "has-content" : ""} ${rightDragOver ? "drag-over" : ""}`}
            onClick={() => !rightHasContent && selectRight()}
            onDragOver={handleDragOver}
            onDragEnter={(e) => { e.preventDefault(); setRightDragOver(true); }}
            onDragLeave={() => setRightDragOver(false)}
            onDrop={handleDropRight}
          >
            {rightHasContent ? (
              <>
                <div className="drop-zone-actions">
                  {rightPath && (
                    <>
                      <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); handleSave(rightPath, rightName); }}>Save</button>
                      <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); handleReveal(rightPath); }}>Reveal</button>
                    </>
                  )}
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
        <button className="btn btn-primary" disabled={!leftHasContent || busy} onClick={handleEncrypt}>
          {busy ? "..." : "Encrypt \u00BB"}
        </button>
        <button className="btn btn-primary" disabled={!rightHasContent || busy} onClick={handleDecrypt}>
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
