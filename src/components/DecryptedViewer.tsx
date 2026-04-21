import React from "react";

/**
 * Render action returned by the Rust backend after decryption.
 *
 * - Inline: WebView can render it (image, video, audio, text, PDF).
 *   Contains a ready-to-use data URI.
 * - External: opened with system default app; just shows a status message.
 * - Unknown: binary blob; shows hex preview and a "Save As" option.
 */
type RenderAction =
  | { kind: "Inline"; mime: string; extension: string; data_base64: string; data_url: string; category: string }
  | { kind: "External"; mime: string; extension: string; temp_path: string }
  | { kind: "Unknown"; size_bytes: number; hex_preview: string };

interface Props {
  render: RenderAction;
}

const DecryptedViewer: React.FC<Props> = ({ render }) => {
  switch (render.kind) {
    case "Inline":
      return <InlineViewer {...render} />;
    case "External":
      return (
        <div className="viewer-external">
          <p>
            Opened with system default application.
          </p>
          <p className="meta">
            {render.mime} &middot; {render.extension}
          </p>
          <p className="meta path">{render.temp_path}</p>
        </div>
      );
    case "Unknown":
      return (
        <div className="viewer-unknown">
          <p>{render.size_bytes.toLocaleString()} bytes (unknown type)</p>
          <pre className="hex-preview">{formatHex(render.hex_preview)}</pre>
        </div>
      );
  }
};

const InlineViewer: React.FC<{
  mime: string;
  extension: string;
  data_base64: string;
  data_url: string;
  category: string;
}> = ({ mime, data_base64, data_url, category }) => {
  switch (category) {
    case "Image":
      return (
        <div className="viewer-image">
          <img src={data_url} alt="Decrypted content" style={{ maxWidth: "100%" }} />
        </div>
      );

    case "Video":
      return (
        <div className="viewer-video">
          <video controls style={{ maxWidth: "100%" }}>
            <source src={data_url} type={mime} />
            Your browser does not support this video format.
          </video>
        </div>
      );

    case "Audio":
      return (
        <div className="viewer-audio">
          <audio controls>
            <source src={data_url} type={mime} />
            Your browser does not support this audio format.
          </audio>
        </div>
      );

    case "Text": {
      // Decode base64 to display as text
      const text = atob(data_base64);
      // If it looks like JSON, try to pretty-print it
      let display = text;
      if (mime === "application/json") {
        try {
          display = JSON.stringify(JSON.parse(text), null, 2);
        } catch {
          /* keep raw */
        }
      }
      return (
        <div className="viewer-text">
          <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
            {display}
          </pre>
        </div>
      );
    }

    case "Pdf":
      return (
        <div className="viewer-pdf">
          <embed
            src={data_url}
            type="application/pdf"
            width="100%"
            style={{ height: "80vh" }}
          />
        </div>
      );

    default:
      return <p>Unsupported inline category: {category}</p>;
  }
};

/** Format a hex string into rows of 32 hex chars (16 bytes) */
function formatHex(hex: string): string {
  const lines: string[] = [];
  for (let i = 0; i < hex.length; i += 32) {
    const chunk = hex.slice(i, i + 32);
    // Insert a space every 2 chars
    const spaced = chunk.replace(/../g, "$& ").trim();
    const offset = (i / 2).toString(16).padStart(8, "0");
    lines.push(`${offset}  ${spaced}`);
  }
  return lines.join("\n");
}

export default DecryptedViewer;
export type { RenderAction };
