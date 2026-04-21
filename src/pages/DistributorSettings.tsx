import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";

interface Applicant {
  user_id: string;
  display_name: string;
  gpg_fingerprint: string;
  created_at: string;
  revoked: boolean;
}

interface SetRevokedResult {
  refreshed_users: string[];
}

export default function DistributorSettings() {
  const [users, setUsers] = useState<Applicant[]>([]);
  const [view, setView] = useState<"list" | "add">("list");
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(null);
  const [redistNotice, setRedistNotice] = useState<{ names: string[]; action: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<Applicant | null>(null);

  const refresh = async () => {
    try { setUsers(await invoke<Applicant[]>("list_gpg_keys")); } catch (_) {}
  };

  useEffect(() => { refresh(); }, []);

  const toggleRevoke = async (user: Applicant) => {
    try {
      const result = await invoke<SetRevokedResult>("set_user_revoked", { userId: user.user_id, revoked: !user.revoked });
      const action = user.revoked ? "restored" : "revoked";
      setStatus({ ok: true, msg: `${user.display_name} ${action}.` });
      if (result.refreshed_users.length > 0) {
        setRedistNotice({ names: result.refreshed_users, action });
      }
      refresh();
    } catch (e: any) {
      setStatus({ ok: false, msg: String(e) });
    }
  };

  const downloadKey = async (user: Applicant) => {
    try {
      const dest = await save({
        title: "Save subscriber key",
        defaultPath: `${user.display_name.replace(/\s+/g, "_")}_key.pgp`,
        filters: [{ name: "PGP Encrypted Key", extensions: ["pgp"] }, { name: "All files", extensions: ["*"] }],
      });
      if (!dest) return;
      await invoke("export_user_key", { userId: user.user_id, destPath: dest });
      setStatus({ ok: true, msg: `Key saved to ${dest}` });
    } catch (e: any) {
      setStatus({ ok: false, msg: `Export failed: ${e}` });
    }
  };

  const executeDelete = async () => {
    if (!confirmDelete) return;
    try {
      await invoke("delete_user", { userId: confirmDelete.user_id });
      setStatus({ ok: true, msg: `${confirmDelete.display_name} permanently deleted.` });
      refresh();
    } catch (e: any) {
      setStatus({ ok: false, msg: String(e) });
    } finally {
      setConfirmDelete(null);
    }
  };

  const handleAdded = () => {
    setView("list");
    refresh();
  };

  if (view === "add") {
    return <AddSubscriber onBack={() => setView("list")} onAdded={handleAdded} />;
  }

  return (
    <div className="page">
      {status && (
        <div className={status.ok ? "alert alert-ok" : "alert alert-err"}>
          {status.msg}
          <button
            onClick={() => setStatus(null)}
            style={{ float: "right", background: "none", border: "none", color: "inherit", cursor: "pointer" }}
          >x</button>
        </div>
      )}

      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <div className="card-title" style={{ margin: 0 }}>Subscribers ({users.length})</div>
          <button className="btn btn-primary btn-sm" onClick={() => setView("add")}>
            + Add Subscriber
          </button>
        </div>

        {users.length === 0 ? (
          <p style={{ color: "var(--text3)", textAlign: "center", padding: "32px 0" }}>
            No subscribers yet. Click "+ Add Subscriber" to get started.
          </p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Fingerprint</th>
                  <th>Status</th>
                  <th style={{ width: 220, textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.user_id}>
                    <td>{u.display_name}</td>
                    <td className="mono">{u.gpg_fingerprint.slice(0, 16)}…</td>
                    <td>
                      <span className={u.revoked ? "badge badge-no" : "badge badge-ok"}>
                        {u.revoked ? "Revoked" : "Active"}
                      </span>
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <div className="btn-row" style={{ margin: 0, justifyContent: "flex-end" }}>
                        <button className="btn btn-sm btn-outline" onClick={() => downloadKey(u)}>
                          Key ↓
                        </button>
                        <button
                          className={`btn btn-sm ${u.revoked ? "btn-outline" : "btn-danger"}`}
                          onClick={() => toggleRevoke(u)}
                        >
                          {u.revoked ? "Restore" : "Revoke"}
                        </button>
                        <button
                          className="btn btn-sm btn-outline"
                          style={{ color: "var(--danger)", borderColor: "var(--danger)" }}
                          onClick={() => setConfirmDelete(u)}
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

      {/* Key redistribution reminder */}
      {redistNotice && (
        <div className="dialog-overlay" onClick={() => setRedistNotice(null)}>
          <div className="dialog" onClick={(e) => e.stopPropagation()}>
            <h3>Key Redistribution Required</h3>
            <p>
              The following subscriber{redistNotice.names.length > 1 ? "s have" : " has"} had their
              broadcast key refreshed server-side:
            </p>
            <ul style={{ margin: "8px 0", paddingLeft: 20 }}>
              {redistNotice.names.map((n) => (
                <li key={n}><strong>{n}</strong></li>
              ))}
            </ul>
            <p>
              Please use the <strong>Key &darr;</strong> button to download
              {redistNotice.names.length > 1 ? " their" : " the"} updated key
              file{redistNotice.names.length > 1 ? "s" : ""} and send{" "}
              {redistNotice.names.length > 1 ? "them" : "it"} to{" "}
              {redistNotice.names.length > 1 ? "each subscriber" : "this subscriber"}.
              They must re-import the new key to decrypt future content.
            </p>
            <div className="btn-row" style={{ justifyContent: "flex-end" }}>
              <button className="btn btn-primary" onClick={() => setRedistNotice(null)}>Understood</button>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirmation */}
      {confirmDelete && (
        <div className="dialog-overlay" onClick={() => setConfirmDelete(null)}>
          <div className="dialog" onClick={(e) => e.stopPropagation()}>
            <h3>Permanently Delete Subscriber</h3>
            <p>
              Delete <strong>{confirmDelete.display_name}</strong>?
              This removes their GPG key, broadcast key, fingerprint, and all ledger records.
              <br /><br /><strong>This cannot be undone.</strong>
            </p>
            <div className="btn-row" style={{ justifyContent: "flex-end" }}>
              <button className="btn btn-outline" onClick={() => setConfirmDelete(null)}>Cancel</button>
              <button className="btn btn-danger" onClick={executeDelete}>Delete Permanently</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---- Add Subscriber sub-view ----

function AddSubscriber({ onBack, onAdded }: { onBack: () => void; onAdded: () => void }) {
  const [armoredKey, setArmoredKey] = useState("");
  const [name, setName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleImport = async () => {
    if (!armoredKey.trim() || !name.trim()) return;
    setLoading(true);
    setError("");
    try {
      await invoke("import_and_assign", {
        armoredKey: armoredKey.trim(),
        displayName: name.trim(),
      });
      onAdded();
    } catch (e: any) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page">
      <div className="card">
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <button className="btn btn-outline btn-sm" onClick={onBack}>&larr; Back</button>
          <div className="card-title" style={{ margin: 0 }}>Add Subscriber</div>
        </div>

        <div className="form-group">
          <label>Display name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Alice" />
        </div>
        <div className="form-group">
          <label>GPG public key (ASCII-armored)</label>
          <textarea
            value={armoredKey}
            onChange={(e) => setArmoredKey(e.target.value)}
            placeholder={"-----BEGIN PGP PUBLIC KEY BLOCK-----\n..."}
            style={{ minHeight: 120 }}
          />
        </div>

        {error && <div className="alert alert-err">{error}</div>}

        <div className="btn-row">
          <button className="btn btn-outline" onClick={onBack}>Cancel</button>
          <button
            className="btn btn-primary"
            onClick={handleImport}
            disabled={loading || !armoredKey.trim() || !name.trim()}
          >
            {loading ? "Processing..." : "Import & Generate Key"}
          </button>
        </div>
      </div>
    </div>
  );
}
