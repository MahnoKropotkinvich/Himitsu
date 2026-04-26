import { useState, useEffect, useMemo, useCallback, useRef } from "react";
import { invoke, Channel } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import { revealItemInDir } from "@tauri-apps/plugin-opener";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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

interface PreviewData {
  category: string;
  preview_base64: string | null;
  preview_data_url: string | null;
}

/** A single file entry in a pane. */
interface PaneFile {
  id: string;
  path: string | null;
  data: string | null; // base64
  name: string;
  size: number;
  isDir: boolean;
  preview: PreviewData | null;
  tempPath?: string;
  originalName?: string;
  extension?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let _nextId = 0;
function genId(): string { return `f${++_nextId}_${Date.now()}`; }

function arrayBufferToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
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

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

function hasPreview(data: PreviewData | null): boolean {
  return !!data && !!data.preview_base64 && ["Image", "Video", "Audio", "Text", "Pdf"].includes(data.category);
}

// ---------------------------------------------------------------------------
// Subcomponents
// ---------------------------------------------------------------------------

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

function PdfPreview({ base64 }: { base64: string }) {
  const blobUrl = useMemo(() => {
    const raw = atob(base64);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return URL.createObjectURL(new Blob([bytes], { type: "application/pdf" }));
  }, [base64]);
  useEffect(() => () => URL.revokeObjectURL(blobUrl), [blobUrl]);
  return <div className="inline-preview"><iframe src={blobUrl} style={{ width: "100%", height: "100%", border: "none" }} /></div>;
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function Workspace() {
  const [leftFiles, setLeftFiles] = useState<PaneFile[]>([]);
  const [rightFiles, setRightFiles] = useState<PaneFile[]>([]);

  const [dialog, setDialog] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [leftDragOver, setLeftDragOver] = useState(false);
  const [rightDragOver, setRightDragOver] = useState(false);
  const [fullscreenPreview, setFullscreenPreview] = useState<PreviewData | null>(null);

  const nativeDropTime = useRef(0);
  const leftPanelRef = useRef<HTMLDivElement>(null);
  const rightPanelRef = useRef<HTMLDivElement>(null);

  /** Detect which pane a screen coordinate falls in. Works for both row and column layouts. */
  const detectPane = useCallback((x: number, y: number): "left" | "right" => {
    const leftRect = leftPanelRef.current?.getBoundingClientRect();
    if (leftRect) {
      if (x >= leftRect.left && x <= leftRect.right && y >= leftRect.top && y <= leftRect.bottom) {
        return "left";
      }
    }
    return "right";
  }, []);

  // ---- Build PaneFile from various sources ----

  const fileFromPath = useCallback(async (filePath: string): Promise<PaneFile> => {
    const info: FileInfo = await invoke("get_file_info", { path: filePath });
    return {
      id: genId(), path: filePath, data: null,
      name: info.name, size: info.size, isDir: info.is_dir,
      preview: { category: info.category, preview_base64: info.preview_base64, preview_data_url: info.preview_data_url },
    };
  }, []);

  const fileFromMemory = useCallback((name: string, size: number, mime: string, base64: string): PaneFile => {
    const category = guessCategoryFromMime(mime);
    return {
      id: genId(), path: null, data: base64,
      name, size, isDir: false,
      preview: { category, preview_base64: base64, preview_data_url: `data:${mime};base64,${base64}` },
    };
  }, []);

  // ---- Tauri native drag-drop ----
  useEffect(() => {
    const unlisten = listen<{ paths: string[]; position: { x: number; y: number } }>(
      "tauri://drag-drop",
      async (event) => {
        const paths = event.payload.paths;
        if (!paths || paths.length === 0) return;
        nativeDropTime.current = Date.now();

        const newFiles: PaneFile[] = [];
        for (const p of paths) {
          try { newFiles.push(await fileFromPath(p)); } catch (e) { console.error("drag-drop:", e); }
        }
        if (newFiles.length === 0) return;

        const side = detectPane(event.payload.position.x, event.payload.position.y);
        if (side === "left") {
          setLeftFiles(prev => [...prev, ...newFiles]);
        } else {
          setRightFiles(prev => [...prev, ...newFiles]);
        }
      }
    );
    return () => { unlisten.then(fn => fn()); };
  }, [fileFromPath, detectPane]);

  // ---- HTML5 drag-drop (for in-memory content like browser-dragged files) ----
  const handleDragOver = useCallback((e: React.DragEvent) => { e.preventDefault(); e.stopPropagation(); }, []);

  const handleDrop = useCallback(async (e: React.DragEvent, side: "left" | "right") => {
    e.preventDefault();
    e.stopPropagation();
    if (side === "left") setLeftDragOver(false); else setRightDragOver(false);
    if (Date.now() - nativeDropTime.current < 500) return;

    const results: PaneFile[] = [];
    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const buf = await file.arrayBuffer();
        const base64 = arrayBufferToBase64(buf);
        results.push(fileFromMemory(file.name, file.size, file.type || "application/octet-stream", base64));
      }
    }
    if (results.length === 0) return;

    if (side === "left") {
      setLeftFiles(prev => [...prev, ...results]);
    } else {
      setRightFiles(prev => [...prev, ...results]);
    }
  }, [fileFromMemory]);

  // ---- Clipboard paste — supports both panes (left half → plaintext, right half → ciphertext) ----
  useEffect(() => {
    const handlePaste = async (e: ClipboardEvent) => {
      const items = e.clipboardData?.items;
      if (!items) return;

      const newFiles: PaneFile[] = [];

      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (item.kind === "file") {
          const file = item.getAsFile();
          if (file) {
            const buf = await file.arrayBuffer();
            const base64 = arrayBufferToBase64(buf);
            newFiles.push(fileFromMemory(
              file.name || `pasted.${file.type.split("/")[1] || "bin"}`,
              file.size, file.type || "application/octet-stream", base64
            ));
          }
        }
      }

      if (newFiles.length === 0) return;
      e.preventDefault();

      // Determine target pane by mouse position
      const mouseX = (window as any).__lastMouseX ?? 0;
      const mouseY = (window as any).__lastMouseY ?? 0;
      const side = detectPane(mouseX, mouseY);
      if (side === "left") {
        setLeftFiles(prev => [...prev, ...newFiles]);
      } else {
        setRightFiles(prev => [...prev, ...newFiles]);
      }
    };

    // Track mouse position for paste target
    const trackMouse = (e: MouseEvent) => { (window as any).__lastMouseX = e.clientX; (window as any).__lastMouseY = e.clientY; };

    window.addEventListener("paste", handlePaste);
    window.addEventListener("mousemove", trackMouse);
    return () => {
      window.removeEventListener("paste", handlePaste);
      window.removeEventListener("mousemove", trackMouse);
    };
  }, [fileFromMemory]);

  // ---- File selection via dialog ----
  const selectLeft = async () => {
    const result = await open({ multiple: true, title: "Select plaintext file(s)" });
    if (!result) return;
    const paths = Array.isArray(result) ? result : [result];
    const newFiles: PaneFile[] = [];
    for (const p of paths) {
      try { newFiles.push(await fileFromPath(p)); } catch (e) { console.error(e); }
    }
    if (newFiles.length > 0) setLeftFiles(prev => [...prev, ...newFiles]);
  };

  const selectRight = async () => {
    const result = await open({
      multiple: true,
      title: "Select ciphertext file(s)",
      filters: [{ name: "Himitsu", extensions: ["himitsu"] }, { name: "All", extensions: ["*"] }],
    });
    if (!result) return;
    const paths = Array.isArray(result) ? result : [result];
    const newFiles: PaneFile[] = [];
    for (const p of paths) {
      try { newFiles.push(await fileFromPath(p)); } catch (e) { console.error(e); }
    }
    if (newFiles.length > 0) setRightFiles(prev => [...prev, ...newFiles]);
  };

  // ---- Remove / clear ----
  const removeLeft = (id: string) => setLeftFiles(prev => prev.filter(f => f.id !== id));
  const removeRight = (id: string) => setRightFiles(prev => prev.filter(f => f.id !== id));
  const clearLeft = () => setLeftFiles([]);
  const clearRight = () => setRightFiles([]);

  // ---- Batch Encrypt (parallel) ----
  const handleEncrypt = async () => {
    if (leftFiles.length === 0) return;
    setBusy(true);

    const results = await Promise.allSettled(leftFiles.map(async (f): Promise<PaneFile | null> => {
      let result: EncryptFileResult;
      if (f.data) {
        result = await invoke("encrypt_content", { dataBase64: f.data, filename: f.name || "dropped" });
      } else if (f.path) {
        const cmd = f.isDir ? "encrypt_folder" : "encrypt_file";
        result = await invoke(cmd, { inputPath: f.path });
      } else return null;

      return {
        id: genId(), path: result.output_path, data: null,
        name: result.output_path.split(/[/\\]/).pop() || "encrypted.himitsu",
        size: result.output_size, isDir: false, preview: null,
      };
    }));

    const encrypted: PaneFile[] = [];
    const errors: string[] = [];
    results.forEach((r, i) => {
      if (r.status === "fulfilled" && r.value) encrypted.push(r.value);
      else if (r.status === "rejected") errors.push(`${leftFiles[i].name}: ${r.reason}`);
    });

    if (encrypted.length > 0) setRightFiles(prev => [...prev, ...encrypted]);
    if (errors.length > 0) setDialog(`Encryption errors:\n${errors.join("\n")}`);
    setBusy(false);
  };

  // ---- Batch Decrypt (parallel) ----
  const handleDecrypt = async () => {
    if (rightFiles.length === 0) return;
    setBusy(true);

    const results = await Promise.allSettled(rightFiles.map(async (f): Promise<PaneFile | null> => {
      if (f.data) {
        const result: DecryptResult = await invoke("decrypt_content", { ciphertextBase64: f.data });
        const r = result.render;
        const name = r.extension ? `decrypted.${r.extension}` : "decrypted";
        const cat = r.category ? String(r.category) : "Binary";
        return {
          id: genId(), path: null, data: r.data_base64 || null,
          name, size: result.size_bytes, isDir: false,
          preview: { category: cat, preview_base64: r.data_base64 || null, preview_data_url: r.data_url || null },
        };
      } else if (f.path) {
        const result: DecryptFileResult = await invoke("decrypt_file", { inputPath: f.path });
        const isFolder = result.category === "Folder";
        const displayName = result.original_name
          || (isFolder ? result.temp_path.split(/[/\\]/).pop() || "folder" : "decrypted." + result.extension);
        return {
          id: genId(), path: result.temp_path, data: null,
          name: displayName, size: result.size, isDir: isFolder,
          preview: { category: result.category, preview_base64: result.preview_base64, preview_data_url: result.preview_data_url },
          tempPath: result.temp_path, originalName: result.original_name ?? undefined, extension: result.extension,
        };
      }
      return null;
    }));

    const decrypted: PaneFile[] = [];
    const errors: string[] = [];
    results.forEach((r, i) => {
      if (r.status === "fulfilled" && r.value) decrypted.push(r.value);
      else if (r.status === "rejected") errors.push(`${rightFiles[i].name}: ${r.reason}`);
    });

    if (decrypted.length > 0) setLeftFiles(prev => [...prev, ...decrypted]);
    if (errors.length > 0) setDialog(`Decryption errors:\n${errors.join("\n")}`);
    setBusy(false);
  };

  // ---- Save / Reveal ----
  const handleSave = async (tempPath: string, defaultName: string) => {
    const dest = await save({ title: "Save file", defaultPath: defaultName });
    if (!dest) return;
    try { await invoke("save_temp_file", { tempPath, destPath: dest }); } catch (e: any) { setDialog(`Save failed:\n${e}`); }
  };

  const handleSaveAll = async (files: PaneFile[]) => {
    const saveable = files.filter(f => f.path);
    if (saveable.length === 0) return;
    const dir = await open({ directory: true, title: "Select destination folder" });
    if (!dir) return;
    const errors: string[] = [];
    for (const f of saveable) {
      try {
        const dest = `${dir}/${f.originalName || f.name}`;
        await invoke("save_temp_file", { tempPath: f.path!, destPath: dest });
      } catch (e: any) {
        errors.push(`${f.name}: ${e}`);
      }
    }
    if (errors.length > 0) setDialog(`Save errors:\n${errors.join("\n")}`);
  };

  const handleReveal = async (path: string) => {
    try { await revealItemInDir(path); } catch (e) { console.error("reveal:", e); }
  };

  // ---- Drag out ----
  const handleDragOut = useCallback(async (e: React.MouseEvent, files: PaneFile[]) => {
    const paths = files.map(f => f.path).filter((p): p is string => !!p);
    if (paths.length === 0) return;
    e.preventDefault();
    e.stopPropagation();
    try {
      const onEvent = new Channel();
      onEvent.onmessage = () => {};
      await invoke("plugin:drag|start_drag", {
        item: paths,
        image: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgAAIAAAUAAXpeqz8AAAAASUVORK5CYII=",
        onEvent,
      });
    } catch (err) {
      console.error("[drag-out]", err);
    }
  }, []);

  // ---- Derived ----
  const leftSingle = leftFiles.length === 1 ? leftFiles[0] : null;
  const rightSingle = rightFiles.length === 1 ? rightFiles[0] : null;
  const leftHasContent = leftFiles.length > 0;
  const rightHasContent = rightFiles.length > 0;

  // ---- Render ----
  return (
    <div className="workspace">
      <div className="workspace-panels">
        {/* LEFT: Plaintext */}
        <div className="panel panel-left" ref={leftPanelRef}>
          <div className="panel-label">
            Plaintext
            {leftFiles.length > 0 && <span className="panel-file-name">{leftFiles.length === 1 ? leftFiles[0].name : `${leftFiles.length} files`}</span>}
          </div>
          <div
            className={`drop-zone ${leftHasContent ? "has-content" : ""} ${leftDragOver ? "drag-over" : ""}`}
            onClick={() => !leftHasContent && selectLeft()}
            onDragOver={handleDragOver}
            onDragEnter={(e) => { e.preventDefault(); setLeftDragOver(true); }}
            onDragLeave={() => setLeftDragOver(false)}
            onDrop={(e) => handleDrop(e, "left")}
          >
            {leftHasContent ? (
              <>
                <div className="drop-zone-actions">
                  {leftSingle?.tempPath && (
                    <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); handleSave(leftSingle.tempPath!, leftSingle.originalName || leftSingle.name); }}>Save</button>
                  )}
                  {!leftSingle && leftFiles.some(f => f.path) && (
                    <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); handleSaveAll(leftFiles); }}>Save All</button>
                  )}
                  {leftSingle?.path && (
                    <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); handleReveal(leftSingle.path!); }}>Reveal</button>
                  )}
                  <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); selectLeft(); }}>Add</button>
                  <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); clearLeft(); }}>Clear</button>
                </div>

                {leftSingle ? (
                  <div
                    style={{ cursor: hasPreview(leftSingle.preview) ? "zoom-in" : leftSingle.path ? "grab" : "default", flex: 1, minHeight: 0, display: "flex", flexDirection: "column", justifyContent: hasPreview(leftSingle.preview) ? "flex-start" : "center", width: "100%" }}
                    onMouseDown={(e) => leftSingle.path && handleDragOut(e, [leftSingle])}
                    onClick={() => hasPreview(leftSingle.preview) && setFullscreenPreview(leftSingle.preview)}
                  >
                    {hasPreview(leftSingle.preview) ? (
                      <InlinePreview data={leftSingle.preview!} />
                    ) : (
                      <div className="binary-info">
                        <div className="binary-size">{leftSingle.isDir ? "Folder " : ""}{formatBytes(leftSingle.size)}</div>
                        <div className="binary-name">{leftSingle.name}</div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="file-list">
                    {leftFiles.map(f => (
                      <div key={f.id} className="file-list-item">
                        <span className="file-list-name" title={f.path || f.name}>{f.isDir ? "[ ] " : ""}{f.name}</span>
                        <span className="file-list-size">{formatBytes(f.size)}</span>
                        <button className="file-list-remove" onClick={(e) => { e.stopPropagation(); removeLeft(f.id); }}>x</button>
                      </div>
                    ))}
                  </div>
                )}
              </>
            ) : (
              <div className="drop-hint">Drop file(s) here<br/>or click to select</div>
            )}
          </div>
        </div>

        {/* RIGHT: Ciphertext */}
        <div className="panel" ref={rightPanelRef}>
          <div className="panel-label">
            Ciphertext
            {rightFiles.length > 0 && <span className="panel-file-name">{rightFiles.length === 1 ? rightFiles[0].name : `${rightFiles.length} files`}</span>}
          </div>
          <div
            className={`drop-zone ${rightHasContent ? "has-content" : ""} ${rightDragOver ? "drag-over" : ""}`}
            onClick={() => !rightHasContent && selectRight()}
            onDragOver={handleDragOver}
            onDragEnter={(e) => { e.preventDefault(); setRightDragOver(true); }}
            onDragLeave={() => setRightDragOver(false)}
            onDrop={(e) => handleDrop(e, "right")}
          >
            {rightHasContent ? (
              <>
                <div className="drop-zone-actions">
                  {rightSingle?.path && (
                    <>
                      <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); handleSave(rightSingle.path!, rightSingle.name); }}>Save</button>
                      <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); handleReveal(rightSingle.path!); }}>Reveal</button>
                    </>
                  )}
                  {!rightSingle && rightFiles.some(f => f.path) && (
                    <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); handleSaveAll(rightFiles); }}>Save All</button>
                  )}
                  <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); selectRight(); }}>Add</button>
                  <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); clearRight(); }}>Clear</button>
                </div>

                {rightSingle ? (
                  <div
                    style={{ cursor: rightSingle.path ? "grab" : "default", flex: 1, minHeight: 0, display: "flex", flexDirection: "column", justifyContent: "center", width: "100%" }}
                    onMouseDown={(e) => rightSingle.path && handleDragOut(e, [rightSingle])}
                  >
                    <div className="binary-info">
                      <div className="binary-size">{formatBytes(rightSingle.size)}</div>
                      <div className="binary-name">{rightSingle.name}</div>
                    </div>
                  </div>
                ) : (
                  <div className="file-list">
                    {rightFiles.map(f => (
                      <div key={f.id} className="file-list-item">
                        <span className="file-list-name" title={f.path || f.name}>{f.name}</span>
                        <span className="file-list-size">{formatBytes(f.size)}</span>
                        <button className="file-list-remove" onClick={(e) => { e.stopPropagation(); removeRight(f.id); }}>x</button>
                      </div>
                    ))}
                  </div>
                )}
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
          {busy ? "..." : `Encrypt ${leftFiles.length > 1 ? `(${leftFiles.length})` : ""} \u00BB`}
        </button>
        <button className="btn btn-primary" disabled={!rightHasContent || busy} onClick={handleDecrypt}>
          {busy ? "..." : `\u00AB Decrypt ${rightFiles.length > 1 ? `(${rightFiles.length})` : ""}`}
        </button>
      </div>

      {/* Fullscreen preview modal */}
      {fullscreenPreview && (
        <div className="fullscreen-overlay" onClick={() => setFullscreenPreview(null)}>
          <div className="fullscreen-content" onClick={(e) => e.stopPropagation()}>
            <button className="fullscreen-close" onClick={() => setFullscreenPreview(null)}>x</button>
            <InlinePreview data={fullscreenPreview} />
          </div>
        </div>
      )}

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
