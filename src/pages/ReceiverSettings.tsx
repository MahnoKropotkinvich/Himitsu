import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface ReceiverKeyInfo {
  id: string;
  label: string;
  created_at: string;
  active: boolean;
}

interface Props {
  onKeyChanged: () => void;
}

export default function ReceiverSettings({ onKeyChanged }: Props) {
  const [keys, setKeys] = useState<ReceiverKeyInfo[]>([]);
  const [view, setView] = useState<"list" | "add">("list");
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<ReceiverKeyInfo | null>(null);

  const refresh = async () => {
    try { setKeys(await invoke<ReceiverKeyInfo[]>("list_keys")); } catch (_) {}
  };

  useEffect(() => { refresh(); }, []);

  const activate = async (key: ReceiverKeyInfo) => {
    try {
      await invoke("set_active_key", { keyId: key.id });
      setStatus({ ok: true, msg: `"${key.label}" is now the active decryption key.` });
      refresh();
      onKeyChanged();
    } catch (e: any) {
      setStatus({ ok: false, msg: String(e) });
    }
  };

  const executeDelete = async () => {
    if (!confirmDelete) return;
    try {
      await invoke("delete_key", { keyId: confirmDelete.id });
      setStatus({ ok: true, msg: `"${confirmDelete.label}" deleted.` });
      refresh();
      onKeyChanged();
    } catch (e: any) {
      setStatus({ ok: false, msg: String(e) });
    } finally {
      setConfirmDelete(null);
    }
  };

  const handleAdded = () => {
    setView("list");
    refresh();
    onKeyChanged();
  };

  if (view === "add") {
    return <AddReceiverKey onBack={() => setView("list")} onAdded={handleAdded} />;
  }

  return (
    <div className="page">
      {status && (
        <div className={status.ok ? "alert alert-ok" : "alert alert-err"}>
          {status.msg}
          <button onClick={() => setStatus(null)} style={{ float: "right", background: "none", border: "none", color: "inherit", cursor: "pointer" }}>x</button>
        </div>
      )}

      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <div className="card-title" style={{ margin: 0 }}>Decryption Keys ({keys.length})</div>
          <button className="btn btn-primary btn-sm" onClick={() => setView("add")}>+ Add Key</button>
        </div>

        {keys.length === 0 ? (
          <p style={{ color: "var(--text3)", textAlign: "center", padding: "32px 0" }}>
            No decryption keys yet. Click "+ Add Key" to import one from your distributor.
          </p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Label</th>
                  <th>Added</th>
                  <th>Status</th>
                  <th style={{ width: 180, textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {keys.map((k) => (
                  <tr key={k.id}>
                    <td>{k.label}</td>
                    <td>{new Date(k.created_at).toLocaleDateString()}</td>
                    <td>
                      {k.active
                        ? <span className="badge badge-ok">Active</span>
                        : <span className="badge" style={{ background: "rgba(255,255,255,.05)", color: "var(--text3)" }}>Inactive</span>
                      }
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <div className="btn-row" style={{ margin: 0, justifyContent: "flex-end" }}>
                        {!k.active && (
                          <button className="btn btn-sm btn-primary" onClick={() => activate(k)}>
                            Use
                          </button>
                        )}
                        <button
                          className="btn btn-sm btn-outline"
                          style={{ color: "var(--danger)", borderColor: "var(--danger)" }}
                          onClick={() => setConfirmDelete(k)}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {confirmDelete && (
        <div className="dialog-overlay" onClick={() => setConfirmDelete(null)}>
          <div className="dialog" onClick={(e) => e.stopPropagation()}>
            <h3>Delete Decryption Key</h3>
            <p>
              Delete <strong>"{confirmDelete.label}"</strong>?
              You will need to re-import it from your distributor to decrypt content again.
            </p>
            <div className="btn-row" style={{ justifyContent: "flex-end" }}>
              <button className="btn btn-outline" onClick={() => setConfirmDelete(null)}>Cancel</button>
              <button className="btn btn-danger" onClick={executeDelete}>Delete</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---- Add Key sub-view ----

function AddReceiverKey({ onBack, onAdded }: { onBack: () => void; onAdded: () => void }) {
  const [label, setLabel] = useState("");
  const [gpgPrivKey, setGpgPrivKey] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [encryptedUsk, setEncryptedUsk] = useState<Uint8Array | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setEncryptedUsk(new Uint8Array(reader.result as ArrayBuffer));
    reader.readAsArrayBuffer(file);
  };

  const handleImport = async () => {
    if (!encryptedUsk || !gpgPrivKey.trim() || !label.trim()) return;
    setLoading(true);
    setError("");
    try {
      await invoke("import_key", {
        encryptedBytes: Array.from(encryptedUsk),
        armoredSecretKey: gpgPrivKey.trim(),
        passphrase,
        label: label.trim(),
      });
      onAdded();
    } catch (e: any) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const ready = !!encryptedUsk && !!gpgPrivKey.trim() && !!label.trim();

  return (
    <div className="page">
      <div className="card">
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <button className="btn btn-outline btn-sm" onClick={onBack}>&larr; Back</button>
          <div className="card-title" style={{ margin: 0 }}>Add Decryption Key</div>
        </div>

        <div className="form-group">
          <label>Label (to identify this key)</label>
          <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Work key" />
        </div>

        <div className="form-group">
          <label>Your GPG private key (ASCII-armored)</label>
          <textarea
            value={gpgPrivKey}
            onChange={(e) => setGpgPrivKey(e.target.value)}
            placeholder={"-----BEGIN PGP PRIVATE KEY BLOCK-----\n..."}
            style={{ minHeight: 100 }}
          />
        </div>

        <div className="form-group">
          <label>Passphrase (leave empty if none)</label>
          <input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} placeholder="Optional" />
        </div>

        <div className="form-group">
          <label>Encrypted user key file (.pgp) from your distributor</label>
          <input type="file" onChange={handleFile} accept=".pgp,.gpg,.asc" />
          {encryptedUsk && (
            <p style={{ fontSize: 11, color: "var(--text2)", marginTop: 4 }}>
              Loaded {encryptedUsk.length} bytes
            </p>
          )}
        </div>

        {error && <div className="alert alert-err">{error}</div>}

        <div className="btn-row">
          <button className="btn btn-outline" onClick={onBack}>Cancel</button>
          <button className="btn btn-primary" onClick={handleImport} disabled={loading || !ready}>
            {loading ? "Decrypting..." : "Decrypt & Save Key"}
          </button>
        </div>
      </div>
    </div>
  );
}
