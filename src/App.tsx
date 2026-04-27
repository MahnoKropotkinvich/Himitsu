import { useState, useEffect, useCallback } from "react";
import "./App.css";
import DistributorSettings from "./pages/DistributorSettings";
import ReceiverSettings from "./pages/ReceiverSettings";
import Workspace from "./pages/Workspace";
import { invoke } from "@tauri-apps/api/core";

type Tab = "workspace" | "distributor" | "receiver";

interface SharedAndroidFile {
  name: string;
  size: number;
  dataBase64: string;
  mimeType?: string;
}

export interface PendingReceiverKey {
  name: string;
  bytes: Uint8Array;
}

export interface NamespaceInfo {
  id: string;
  name: string;
  created_at: string;
  total_slots: number;
  available: number;
  assigned: number;
  revoked: number;
  deleted: number;
}

export default function App() {
  const [tab, setTab] = useState<Tab>("workspace");
  const [ready, setReady] = useState(false);
  const [uskB64, setUskB64] = useState("");
  const [pendingReceiverKey, setPendingReceiverKey] = useState<PendingReceiverKey | null>(null);
  const [pendingWorkspaceShares, setPendingWorkspaceShares] = useState<SharedAndroidFile[] | null>(null);
  const [shareChoice, setShareChoice] = useState<SharedAndroidFile[] | null>(null);

  // Namespace state (managed here, passed to Distributor)
  const [namespaces, setNamespaces] = useState<NamespaceInfo[]>([]);
  const [activeNs, setActiveNs] = useState<string | null>(null);

  const loadActiveKey = useCallback(async () => {
    try {
      const b64 = await invoke<string>("get_active_key");
      setUskB64(b64);
    } catch (_) {
      setUskB64("");
    }
  }, []);

  const loadNamespaces = useCallback(async () => {
    try {
      const list = await invoke<NamespaceInfo[]>("list_namespaces");
      setNamespaces(list);
      const active = await invoke<string | null>("get_active_namespace");
      setActiveNs(active);
    } catch (e) {
      console.error("Failed to load namespaces:", e);
    }
  }, []);

  useEffect(() => {
    (async () => {
      try {
        await invoke("ensure_initialized");
        await loadActiveKey();
        await loadNamespaces();
      } catch (e) {
        console.error("Init failed:", e);
      }
      setReady(true);
    })();
  }, [loadActiveKey, loadNamespaces]);

  useEffect(() => {
    const looksLikeReceiverKey = (file: SharedAndroidFile) => {
      const name = file.name.toLowerCase();
      const mimeType = (file.mimeType || "").toLowerCase();
      if (name.endsWith(".pgp") || name.endsWith(".gpg") || name.endsWith(".asc")) return true;
      if (mimeType.includes("pgp") || mimeType.includes("gpg")) return true;
      try {
        const text = atob(file.dataBase64).slice(0, 8192);
        return text.includes("-----BEGIN PGP MESSAGE-----");
      } catch (_) {
        return false;
      }
    };

    const sendToWorkspace = (files: SharedAndroidFile[]) => {
      setTab("workspace");
      setPendingWorkspaceShares(files);
    };

    const routeSharedFiles = (files: SharedAndroidFile[]) => {
      if (!files.length) return;
      const receiverKey = files.find(looksLikeReceiverKey);
      if (receiverKey) {
        setShareChoice(files);
      } else {
        sendToWorkspace(files);
      }
    };

    const handleShareReceived = (event: Event) => {
      (window as any).__HIMITSU_PENDING_SHARES = [];
      routeSharedFiles((event as CustomEvent<SharedAndroidFile[]>).detail || []);
    };

    window.addEventListener("share-received", handleShareReceived);

    const pending = (window as any).__HIMITSU_PENDING_SHARES as SharedAndroidFile[] | undefined;
    if (pending?.length) {
      (window as any).__HIMITSU_PENDING_SHARES = [];
      routeSharedFiles(pending);
    }

    return () => window.removeEventListener("share-received", handleShareReceived);
  }, []);

  const importSharedReceiverKey = useCallback(() => {
    const receiverKey = shareChoice?.find((file) => {
      const name = file.name.toLowerCase();
      const mimeType = (file.mimeType || "").toLowerCase();
      if (name.endsWith(".pgp") || name.endsWith(".gpg") || name.endsWith(".asc")) return true;
      if (mimeType.includes("pgp") || mimeType.includes("gpg")) return true;
      try {
        return atob(file.dataBase64).slice(0, 8192).includes("-----BEGIN PGP MESSAGE-----");
      } catch (_) {
        return false;
      }
    });
    if (!receiverKey) return;
    const raw = atob(receiverKey.dataBase64);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    setPendingReceiverKey({ name: receiverKey.name, bytes });
    setShareChoice(null);
    setTab("receiver");
  }, [shareChoice]);

  const encryptSharedReceiverKey = useCallback(() => {
    if (shareChoice?.length) {
      setTab("workspace");
      setPendingWorkspaceShares(shareChoice);
    }
    setShareChoice(null);
  }, [shareChoice]);

  const handleSelectNamespace = useCallback(
    async (nsId: string) => {
      try {
        await invoke("set_active_namespace", { namespaceId: nsId });
        setActiveNs(nsId);
      } catch (e) {
        console.error("Set active namespace failed:", e);
      }
    },
    [],
  );

  if (!ready) {
    return <div className="app-loading"><span>Initializing...</span></div>;
  }

  const activeNsInfo = namespaces.find((ns) => ns.id === activeNs);

  return (
    <div className="app-layout">
      <nav className="tab-bar">
        <button className={tab === "workspace" ? "active" : ""} onClick={() => setTab("workspace")}>
          Encrypt / Decrypt
        </button>
        <button className={tab === "distributor" ? "active" : ""} onClick={() => setTab("distributor")}>
          Distributor{activeNsInfo ? ` (${activeNsInfo.name})` : ""}
        </button>
        <button className={tab === "receiver" ? "active" : ""} onClick={() => setTab("receiver")}>
          Receiver {uskB64 ? " \u2713" : ""}
        </button>
      </nav>

      <main className="main-content">
        {tab === "workspace" && (
          <Workspace
            pendingSharedFiles={pendingWorkspaceShares}
            onPendingSharedFilesConsumed={() => setPendingWorkspaceShares(null)}
          />
        )}
        {tab === "distributor" && (
          <DistributorSettings
            namespaces={namespaces}
            activeNs={activeNs}
            onSelectNamespace={handleSelectNamespace}
            onNamespacesChanged={loadNamespaces}
          />
        )}
        {tab === "receiver" && (
          <ReceiverSettings
            onKeyChanged={loadActiveKey}
            pendingKey={pendingReceiverKey}
            onPendingKeyConsumed={() => setPendingReceiverKey(null)}
          />
        )}
      </main>

      {shareChoice && (
        <div className="dialog-overlay" onClick={() => setShareChoice(null)}>
          <div className="dialog" onClick={(e) => e.stopPropagation()}>
            <h3>Handle PGP File</h3>
            <p>
              {(shareChoice.find((file) => file.name.toLowerCase().endsWith(".pgp") || file.name.toLowerCase().endsWith(".gpg") || file.name.toLowerCase().endsWith(".asc")) || shareChoice[0])?.name || "This file"} looks like a PGP receiver key. What do you want to do?
            </p>
            <div className="btn-row" style={{ justifyContent: "flex-end" }}>
              <button className="btn btn-outline" onClick={() => setShareChoice(null)}>Cancel</button>
              <button className="btn btn-outline" onClick={encryptSharedReceiverKey}>Encrypt as File</button>
              <button className="btn btn-primary" onClick={importSharedReceiverKey}>Import Key</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
