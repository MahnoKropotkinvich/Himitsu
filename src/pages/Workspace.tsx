import { useState, useRef, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { RenderAction } from "../components/DecryptedViewer";

interface DecryptResult {
  success: boolean;
  size_bytes: number;
  render: RenderAction;
  message: string;
}

// --- Detect MIME from magic bytes (client-side, quick check) ---
function detectMime(buf: Uint8Array): string {
  if (buf.length < 4) return "application/octet-stream";
  const h = (i: number) => buf[i];
  // Images
  if (h(0)===0x89 && h(1)===0x50 && h(2)===0x4e && h(3)===0x47) return "image/png";
  if (h(0)===0xff && h(1)===0xd8) return "image/jpeg";
  if (h(0)===0x47 && h(1)===0x49 && h(2)===0x46) return "image/gif";
  if (h(0)===0x52 && h(1)===0x49 && h(2)===0x46 && h(3)===0x46 && buf.length>11 && h(8)===0x57 && h(9)===0x45 && h(10)===0x42 && h(11)===0x50) return "image/webp";
  if (h(0)===0x00 && h(1)===0x00 && h(2)===0x01 && h(3)===0x00) return "image/x-icon";
  // Video
  if (buf.length>11 && h(4)===0x66 && h(5)===0x74 && h(6)===0x79 && h(7)===0x70) return "video/mp4";
  if (h(0)===0x1a && h(1)===0x45 && h(2)===0xdf && h(3)===0xa3) return "video/webm";
  // Audio
  if (h(0)===0x49 && h(1)===0x44 && h(2)===0x33) return "audio/mpeg";
  if (h(0)===0x4f && h(1)===0x67 && h(2)===0x67 && h(3)===0x53) return "audio/ogg";
  if (h(0)===0x52 && h(1)===0x49 && h(2)===0x46 && h(3)===0x46) return "audio/wav";
  if (h(0)===0x66 && h(1)===0x4c && h(2)===0x61 && h(3)===0x43) return "audio/flac";
  // PDF
  if (h(0)===0x25 && h(1)===0x50 && h(2)===0x44 && h(3)===0x46) return "application/pdf";
  // Try UTF-8 text
  try { new TextDecoder("utf-8", { fatal: true }).decode(buf.slice(0, 4096)); return "text/plain"; } catch {}
  return "application/octet-stream";
}

function isRenderable(mime: string): boolean {
  return (
    mime.startsWith("image/") ||
    mime.startsWith("video/") ||
    mime.startsWith("audio/") ||
    mime.startsWith("text/") ||
    mime === "application/json" ||
    mime === "application/pdf"
  );
}

// --- Inline renderer for the plaintext panel ---
function PlaintextPreview({ data, mime }: { data: Uint8Array; mime: string }) {
  const url = useMemo(() => URL.createObjectURL(new Blob([data], { type: mime })), [data, mime]);

  if (mime.startsWith("image/"))
    return <div className="inline-preview"><img src={url} alt="" /></div>;
  if (mime.startsWith("video/"))
    return <div className="inline-preview"><video controls src={url} /></div>;
  if (mime.startsWith("audio/"))
    return <div className="inline-preview"><audio controls src={url} /></div>;
  if (mime === "application/pdf")
    return <div className="inline-preview"><embed src={url} type="application/pdf" style={{ width: "100%", height: "100%" }} /></div>;
  if (mime.startsWith("text/") || mime === "application/json") {
    const text = new TextDecoder().decode(data);
    return <div className="inline-preview"><pre className="text-preview">{text.slice(0, 100000)}</pre></div>;
  }
  // Should not reach here if isRenderable works, but just in case
  return <BinaryInfo size={data.length} name="" />;
}

// --- Binary (non-renderable) file info + download ---
function BinaryInfo({ size, name, onDownload }: { size: number; name: string; onDownload?: () => void }) {
  return (
    <div className="binary-info">
      <div className="binary-size">{formatBytes(size)}</div>
      {name && <div className="binary-name">{name}</div>}
      {onDownload && (
        <button className="btn btn-outline btn-sm" style={{ marginTop: 8 }} onClick={(e) => { e.stopPropagation(); onDownload(); }}>
          Save As...
        </button>
      )}
    </div>
  );
}

export default function Workspace({ uskB64 }: { uskB64: string }) {
  const [leftData, setLeftData] = useState<Uint8Array | null>(null);
  const [leftName, setLeftName] = useState("");
  const [leftMime, setLeftMime] = useState("");
  const [rightData, setRightData] = useState<Uint8Array | null>(null);
  const [rightName, setRightName] = useState("");
  const [dialog, setDialog] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [leftDrag, setLeftDrag] = useState(false);
  const [rightDrag, setRightDrag] = useState(false);

  const leftInput = useRef<HTMLInputElement>(null);
  const rightInput = useRef<HTMLInputElement>(null);

  const loadFile = useCallback((file: File, side: "left" | "right") => {
    const reader = new FileReader();
    reader.onload = () => {
      const bytes = new Uint8Array(reader.result as ArrayBuffer);
      const mime = file.type || detectMime(bytes);
      if (side === "left") {
        setLeftData(bytes); setLeftName(file.name); setLeftMime(mime);
      } else {
        setRightData(bytes); setRightName(file.name);
      }
    };
    reader.readAsArrayBuffer(file);
  }, []);

  const prevent = (e: React.DragEvent) => { e.preventDefault(); e.stopPropagation(); };
  const onDragEnter = (e: React.DragEvent, s: "left"|"right") => { prevent(e); s==="left" ? setLeftDrag(true) : setRightDrag(true); };
  const onDragOver = (e: React.DragEvent) => prevent(e);
  const onDragLeave = (e: React.DragEvent, s: "left"|"right") => {
    prevent(e);
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const {clientX:x,clientY:y} = e;
    if (x<=r.left||x>=r.right||y<=r.top||y>=r.bottom) { s==="left"?setLeftDrag(false):setRightDrag(false); }
  };
  const onDrop = (e: React.DragEvent, s: "left"|"right") => {
    prevent(e);
    s==="left"?setLeftDrag(false):setRightDrag(false);
    const file = e.dataTransfer.files?.[0];
    if (file) loadFile(file, s);
  };

  // --- Encrypt ---
  const handleEncrypt = async () => {
    if (!leftData) return;
    setBusy(true);
    try {
      const b64 = uint8ToBase64(leftData);
      const ctB64: string = await invoke("encrypt_broadcast", {
        plaintextBase64: b64,
        policy: "Access::Broadcast",
      });
      setRightData(base64ToUint8(ctB64));
      setRightName((leftName || "file") + ".himitsu");
    } catch (e: any) {
      setDialog(`Encryption failed:\n${e}`);
    } finally {
      setBusy(false);
    }
  };

  // --- Decrypt ---
  const handleDecrypt = async () => {
    if (!rightData) return;
    if (!uskB64) {
      setDialog("No decryption key loaded.\nGo to the Receiver tab and import a key first.");
      return;
    }
    setBusy(true);
    try {
      const result: DecryptResult = await invoke("decrypt_content", {
        ciphertextJsonBase64: uint8ToBase64(rightData),
        userSecretKeyBase64: uskB64,
      });
      if (result.success && result.render.kind === "Inline") {
        const bytes = base64ToUint8(result.render.data_base64);
        setLeftData(bytes);
        setLeftMime(result.render.mime);
        setLeftName("decrypted." + result.render.extension);
      } else if (result.success && result.render.kind === "External") {
        // Already opened externally
        setLeftData(null); setLeftName(""); setLeftMime("");
      } else if (!result.success) {
        setDialog(`Decryption failed:\n${result.message}`);
      }
    } catch (e: any) {
      setDialog(`Decryption failed:\n${e}`);
    } finally {
      setBusy(false);
    }
  };

  const clearLeft = () => { setLeftData(null); setLeftName(""); setLeftMime(""); };
  const clearRight = () => { setRightData(null); setRightName(""); };

  const downloadFile = (data: Uint8Array, name: string) => {
    const blob = new Blob([data]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name; a.click();
    URL.revokeObjectURL(url);
  };

  const leftRenderable = leftMime ? isRenderable(leftMime) : false;

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
            className={`drop-zone ${leftDrag ? "drag-over" : ""} ${leftData ? "has-content" : ""}`}
            onDragEnter={(e) => onDragEnter(e, "left")}
            onDragOver={onDragOver}
            onDragLeave={(e) => onDragLeave(e, "left")}
            onDrop={(e) => onDrop(e, "left")}
            onClick={() => !leftData && leftInput.current?.click()}
          >
            {leftData ? (
              <>
                <button className="btn btn-outline btn-sm clear-btn" onClick={(e) => { e.stopPropagation(); clearLeft(); }}>Clear</button>
                {leftRenderable ? (
                  <PlaintextPreview data={leftData} mime={leftMime} />
                ) : (
                  <BinaryInfo size={leftData.length} name={leftName} onDownload={() => downloadFile(leftData!, leftName || "plaintext.bin")} />
                )}
              </>
            ) : (
              <div className="drop-hint">Drop file here<br/>or click to select</div>
            )}
          </div>
          <input ref={leftInput} type="file" hidden onChange={(e) => { if (e.target.files?.[0]) loadFile(e.target.files[0], "left"); e.target.value=""; }} />
        </div>

        {/* RIGHT: Ciphertext */}
        <div className="panel">
          <div className="panel-label">
            Ciphertext
            {rightName && <span className="panel-file-name">{rightName}</span>}
          </div>
          <div
            className={`drop-zone ${rightDrag ? "drag-over" : ""} ${rightData ? "has-content" : ""}`}
            onDragEnter={(e) => onDragEnter(e, "right")}
            onDragOver={onDragOver}
            onDragLeave={(e) => onDragLeave(e, "right")}
            onDrop={(e) => onDrop(e, "right")}
            onClick={() => !rightData && rightInput.current?.click()}
          >
            {rightData ? (
              <>
                <div className="drop-zone-actions">
                  <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); downloadFile(rightData!, rightName || "encrypted.himitsu"); }}>Save</button>
                  <button className="btn btn-outline btn-sm" onClick={(e) => { e.stopPropagation(); clearRight(); }}>Clear</button>
                </div>
                <BinaryInfo size={rightData.length} name={rightName} />
              </>
            ) : (
              <div className="drop-hint">Drop ciphertext here<br/>or click to select</div>
            )}
          </div>
          <input ref={rightInput} type="file" hidden onChange={(e) => { if (e.target.files?.[0]) loadFile(e.target.files[0], "right"); e.target.value=""; }} />
        </div>
      </div>

      {/* Action bar */}
      <div className="workspace-actions">
        <button className="btn btn-primary" disabled={!leftData || busy} onClick={handleEncrypt}>
          {busy ? "..." : "Encrypt \u00BB"}
        </button>
        <button className="btn btn-primary" disabled={!rightData || busy} onClick={handleDecrypt}>
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
  return `${(n / 1048576).toFixed(1)} MB`;
}
function uint8ToBase64(b: Uint8Array): string {
  let s=""; for(let i=0;i<b.length;i++) s+=String.fromCharCode(b[i]); return btoa(s);
}
function base64ToUint8(s: string): Uint8Array {
  const b=atob(s); const a=new Uint8Array(b.length); for(let i=0;i<b.length;i++) a[i]=b.charCodeAt(i); return a;
}
