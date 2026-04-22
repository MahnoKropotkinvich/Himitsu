import { useState, useEffect, useCallback } from "react";
import "./App.css";
import DistributorSettings from "./pages/DistributorSettings";
import ReceiverSettings from "./pages/ReceiverSettings";
import Workspace from "./pages/Workspace";
import { invoke } from "@tauri-apps/api/core";

type Tab = "workspace" | "distributor" | "receiver";

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
        {tab === "workspace" && <Workspace />}
        {tab === "distributor" && (
          <DistributorSettings
            namespaces={namespaces}
            activeNs={activeNs}
            onSelectNamespace={handleSelectNamespace}
            onNamespacesChanged={loadNamespaces}
          />
        )}
        {tab === "receiver" && <ReceiverSettings onKeyChanged={loadActiveKey} />}
      </main>
    </div>
  );
}
