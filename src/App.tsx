import { useState, useEffect, useCallback } from "react";
import "./App.css";
import DistributorSettings from "./pages/DistributorSettings";
import ReceiverSettings from "./pages/ReceiverSettings";
import Workspace from "./pages/Workspace";
import { invoke } from "@tauri-apps/api/core";

type Tab = "workspace" | "distributor" | "receiver";

export default function App() {
  const [tab, setTab] = useState<Tab>("workspace");
  const [ready, setReady] = useState(false);
  const [uskB64, setUskB64] = useState("");

  const loadActiveKey = useCallback(async () => {
    try {
      const b64 = await invoke<string>("load_active_receiver_key");
      setUskB64(b64);
    } catch (_) {
      setUskB64("");
    }
  }, []);

  useEffect(() => {
    (async () => {
      try {
        await invoke("ensure_initialized");
        await loadActiveKey();
      } catch (e) {
        console.error("Init failed:", e);
      }
      setReady(true);
    })();
  }, [loadActiveKey]);

  if (!ready) {
    return <div className="app-loading"><span>Initializing...</span></div>;
  }

  return (
    <div className="app-layout">
      <nav className="tab-bar">
        <button className={tab === "workspace" ? "active" : ""} onClick={() => setTab("workspace")}>
          Encrypt / Decrypt
        </button>
        <button className={tab === "distributor" ? "active" : ""} onClick={() => setTab("distributor")}>
          Distributor
        </button>
        <button className={tab === "receiver" ? "active" : ""} onClick={() => setTab("receiver")}>
          Receiver {uskB64 ? " \u2713" : ""}
        </button>
      </nav>

      <main className="main-content">
        {tab === "workspace" && <Workspace uskB64={uskB64} />}
        {tab === "distributor" && <DistributorSettings />}
        {tab === "receiver" && <ReceiverSettings onKeyChanged={loadActiveKey} />}
      </main>
    </div>
  );
}
