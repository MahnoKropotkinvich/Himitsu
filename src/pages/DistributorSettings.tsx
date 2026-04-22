import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import type { NamespaceInfo } from "../App";

interface Applicant {
  user_id: string;
  display_name: string;
  gpg_fingerprint: string;
  created_at: string;
  revoked: boolean;
}

interface Props {
  namespaces: NamespaceInfo[];
  activeNs: string | null;
  onSelectNamespace: (id: string) => void;
  onNamespacesChanged: () => void;
}

export default function DistributorSettings({
  namespaces,
  activeNs,
  onSelectNamespace,
  onNamespacesChanged,
}: Props) {
  const [users, setUsers] = useState<Applicant[]>([]);
  const [view, setView] = useState<"list" | "add">("list");
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<Applicant | null>(null);

  // Namespace creation
  const [showCreateNs, setShowCreateNs] = useState(false);
  const [newNsName, setNewNsName] = useState("");
  const [nsCreating, setNsCreating] = useState(false);

  const refresh = async () => {
    try { setUsers(await invoke<Applicant[]>("list_subscribers")); } catch (_) {}
  };

  useEffect(() => { refresh(); }, [activeNs]);

  const handleCreateNamespace = async () => {
    if (!newNsName.trim()) return;
    setNsCreating(true);
    try {
      await invoke("create_namespace", { name: newNsName.trim() });
      setNewNsName("");
      setShowCreateNs(false);
      onNamespacesChanged();
    } catch (e: any) {
      setStatus({ ok: false, msg: String(e) });
    }
    setNsCreating(false);
  };

  const toggleRevoke = async (user: Applicant) => {
    try {
      await invoke("set_subscriber_revoked", { userId: user.user_id, revoked: !user.revoked });
      const action = user.revoked ? "restored" : "revoked";
      setStatus({ ok: true, msg: `${user.display_name} ${action}.` });
      refresh();
      onNamespacesChanged();
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
      await invoke("export_subscriber_key", { userId: user.user_id, destPath: dest });
      setStatus({ ok: true, msg: `Key saved to ${dest}` });
    } catch (e: any) {
      setStatus({ ok: false, msg: `Export failed: ${e}` });
    }
  };

  const executeDelete = async () => {
    if (!confirmDelete) return;
    try {
      await invoke("delete_subscriber", { userId: confirmDelete.user_id });
      setStatus({ ok: true, msg: `${confirmDelete.display_name} permanently deleted.` });
      refresh();
      onNamespacesChanged();
    } catch (e: any) {
      setStatus({ ok: false, msg: String(e) });
    } finally {
      setConfirmDelete(null);
    }
  };

  const handleAdded = () => {
    setView("list");
    refresh();
    onNamespacesChanged();
  };

  const activeNsInfo = namespaces.find((ns) => ns.id === activeNs);

  if (view === "add") {
    return <AddSubscriber onBack={() => setView("list")} onAdded={handleAdded} />;
  }

  return (
    <div className="distributor-layout">
      {/* Namespace sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">Namespaces</div>
        <ul className="ns-list">
          {namespaces.map((ns) => (
            <li
              key={ns.id}
              className={`ns-item${ns.id === activeNs ? " active" : ""}`}
              onClick={() => onSelectNamespace(ns.id)}
            >
              <span className="ns-name">{ns.name}</span>
              <span className="ns-seats">
                {ns.available}/{ns.total_slots}
              </span>
            </li>
          ))}
        </ul>
        {showCreateNs ? (
          <div className="ns-create-form">
            <input
              type="text"
              placeholder="Namespace name"
              value={newNsName}
              onChange={(e) => setNewNsName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleCreateNamespace()}
              autoFocus
            />
            <div className="btn-row">
              <button className="btn btn-primary btn-sm" onClick={handleCreateNamespace} disabled={nsCreating}>
                {nsCreating ? "..." : "Create"}
              </button>
              <button className="btn btn-outline btn-sm" onClick={() => setShowCreateNs(false)}>
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <button className="btn btn-outline btn-sm ns-create-btn" onClick={() => setShowCreateNs(true)}>
            + New Namespace
          </button>
        )}
      </aside>

      {/* Main content */}
      <div className="distributor-content">
        {!activeNs ? (
          <div className="no-namespace">
            <p>No namespace selected.</p>
            <p>Create a namespace to start distributing keys.</p>
          </div>
        ) : (
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
                <div className="card-title" style={{ margin: 0 }}>
                  {activeNsInfo?.name} — Subscribers ({users.length})
                  <span style={{ marginLeft: 12, fontWeight: 400, textTransform: "none", fontSize: 10, color: "var(--text3)" }}>
                    {activeNsInfo?.available} seats available
                  </span>
                </div>
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
                          <td className="mono">{u.gpg_fingerprint.slice(0, 16)}...</td>
                          <td>
                            <span className={u.revoked ? "badge badge-no" : "badge badge-ok"}>
                              {u.revoked ? "Revoked" : "Active"}
                            </span>
                          </td>
                          <td style={{ textAlign: "right" }}>
                            <div className="btn-row" style={{ margin: 0, justifyContent: "flex-end" }}>
                              <button className="btn btn-sm btn-outline" onClick={() => downloadKey(u)}>
                                Key
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

            {/* Delete confirmation */}
            {confirmDelete && (
              <div className="dialog-overlay" onClick={() => setConfirmDelete(null)}>
                <div className="dialog" onClick={(e) => e.stopPropagation()}>
                  <h3>Permanently Delete Subscriber</h3>
                  <p>
                    Delete <strong>{confirmDelete.display_name}</strong>?
                    <br /><br />
                    This will permanently destroy their key slot. The seat will <strong>not</strong> be
                    returned to the available pool — the namespace's remaining capacity will
                    decrease by one.
                    <br /><br />
                    If you only want to suspend access, use <strong>Revoke</strong> instead.
                    <br /><br />
                    <strong>This cannot be undone.</strong>
                  </p>
                  <div className="btn-row" style={{ justifyContent: "flex-end" }}>
                    <button className="btn btn-outline" onClick={() => setConfirmDelete(null)}>Cancel</button>
                    <button className="btn btn-danger" onClick={executeDelete}>Delete Permanently</button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
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
      await invoke("add_subscriber", {
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
    <div className="distributor-layout">
      <div className="distributor-content">
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
      </div>
    </div>
  );
}
