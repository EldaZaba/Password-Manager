import { invoke } from "@tauri-apps/api/core";
import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";
import { ChangeEvent, FormEvent, useEffect, useMemo, useRef, useState } from "react";

type Theme = "light" | "dark";
type SortMode = "serviceAsc" | "serviceDesc" | "updatedDesc";

interface AppStatus {
  initialized: boolean;
  unlocked: boolean;
}

interface PasswordEntry {
  id: string;
  service: string;
  username: string;
  password: string;
  notes: string;
  url: string;
  createdAt: number;
  updatedAt: number;
}

interface EntryForm {
  service: string;
  username: string;
  password: string;
  notes: string;
  url: string;
}

interface GeneratorOptions {
  length: number;
  includeNumbers: boolean;
  includeSymbols: boolean;
}

const EMPTY_FORM: EntryForm = { service: "", username: "", password: "", notes: "", url: "" };
const INACTIVITY_MS = 5 * 60 * 1000;

function App() {
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [entries, setEntries] = useState<PasswordEntry[]>([]);
  const [masterPassword, setMasterPassword] = useState("");
  const [masterConfirm, setMasterConfirm] = useState("");
  const [form, setForm] = useState<EntryForm>(EMPTY_FORM);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<SortMode>("updatedDesc");
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const [generator, setGenerator] = useState<GeneratorOptions>({
    length: 16,
    includeNumbers: true,
    includeSymbols: true,
  });
  const [importPayload, setImportPayload] = useState("");
  const [importFileName, setImportFileName] = useState("");
  const [importMasterPassword, setImportMasterPassword] = useState("");
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = localStorage.getItem("theme");
    if (stored === "light" || stored === "dark") {
      return stored;
    }
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });

  const inactivityTimer = useRef<number | null>(null);
  const clipboardTimer = useRef<number | null>(null);

  const visibleEntries = useMemo(() => {
    const needle = search.toLowerCase().trim();
    const filtered = entries.filter((entry) => {
      if (!needle) return true;
      return (
        entry.service.toLowerCase().includes(needle) ||
        entry.username.toLowerCase().includes(needle) ||
        entry.notes.toLowerCase().includes(needle) ||
        entry.url.toLowerCase().includes(needle)
      );
    });

    filtered.sort((a, b) => {
      if (sort === "serviceAsc") return a.service.localeCompare(b.service);
      if (sort === "serviceDesc") return b.service.localeCompare(a.service);
      return b.updatedAt - a.updatedAt;
    });
    return filtered;
  }, [entries, search, sort]);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    localStorage.setItem("theme", theme);
  }, [theme]);

  useEffect(() => {
    void refreshStatus();
  }, []);

  useEffect(() => {
    if (!status?.unlocked) {
      if (inactivityTimer.current) window.clearTimeout(inactivityTimer.current);
      return;
    }
    const touch = () => {
      if (inactivityTimer.current) window.clearTimeout(inactivityTimer.current);
      inactivityTimer.current = window.setTimeout(() => {
        void lockVault("Vault locked after 5 minutes of inactivity.");
      }, INACTIVITY_MS);
    };
    const events: Array<keyof WindowEventMap> = [
      "mousemove",
      "keydown",
      "mousedown",
      "touchstart",
      "scroll",
    ];
    events.forEach((name) => window.addEventListener(name, touch));
    touch();
    return () => {
      if (inactivityTimer.current) window.clearTimeout(inactivityTimer.current);
      events.forEach((name) => window.removeEventListener(name, touch));
    };
  }, [status?.unlocked]);

  useEffect(() => {
    return () => {
      if (clipboardTimer.current) window.clearTimeout(clipboardTimer.current);
      if (inactivityTimer.current) window.clearTimeout(inactivityTimer.current);
    };
  }, []);

  const clearMessages = () => {
    setError("");
    setInfo("");
  };

  const resetForm = () => {
    setForm(EMPTY_FORM);
    setEditingId(null);
  };

  async function refreshStatus() {
    try {
      const appStatus = await invoke<AppStatus>("get_app_status");
      setStatus(appStatus);
      if (appStatus.unlocked) {
        const rows = await invoke<unknown>("get_entries");
        setEntries(normalizeEntries(rows));
      }
    } catch (err) {
      setError(readableError(err));
    }
  }

  async function setupVault(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    clearMessages();
    if (masterPassword !== masterConfirm) {
      setError("Master password confirmation does not match.");
      return;
    }
    try {
      const rows = await invoke<unknown>("initialize_master_password", { masterPassword });
      setEntries(normalizeEntries(rows));
      setStatus({ initialized: true, unlocked: true });
      setMasterPassword("");
      setMasterConfirm("");
      setInfo("Vault created.");
    } catch (err) {
      setError(readableError(err));
    }
  }

  async function unlockVault(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    clearMessages();
    try {
      const rows = await invoke<unknown>("login", { masterPassword });
      setEntries(normalizeEntries(rows));
      setStatus({ initialized: true, unlocked: true });
      setMasterPassword("");
      setMasterConfirm("");
      setInfo("Vault unlocked.");
    } catch (err) {
      setError(readableError(err));
    }
  }

  async function lockVault(message?: string) {
    clearMessages();
    try {
      await invoke("lock_vault");
    } catch {
      // local lock still applies
    }
    setStatus({ initialized: true, unlocked: false });
    setEntries([]);
    setRevealed({});
    resetForm();
    if (message) setInfo(message);
  }

  async function saveEntry(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    clearMessages();
    try {
      if (editingId) {
        const updatedRaw = await invoke<unknown>("update_entry", {
          input: { id: editingId, ...form },
        });
        const updated = normalizeEntry(updatedRaw);
        if (!updated) throw new Error("Invalid entry payload received from backend.");
        setEntries((current) => current.map((entry) => (entry.id === updated.id ? updated : entry)));
        setInfo("Entry updated.");
      } else {
        const createdRaw = await invoke<unknown>("add_entry", { input: form });
        const created = normalizeEntry(createdRaw);
        if (!created) throw new Error("Invalid entry payload received from backend.");
        setEntries((current) => [...current, created]);
        setInfo("Entry added.");
      }
      resetForm();
    } catch (err) {
      setError(readableError(err));
    }
  }

  async function deleteEntry(id: string) {
    clearMessages();
    if (!window.confirm("Delete this entry?")) return;
    try {
      await invoke("delete_entry", { id });
      setEntries((current) => current.filter((entry) => entry.id !== id));
      setInfo("Entry deleted.");
    } catch (err) {
      setError(readableError(err));
    }
  }

  async function generatePassword() {
    clearMessages();
    try {
      const password = await invoke<string>("generate_password", { request: generator });
      setForm((current) => ({ ...current, password }));
      setInfo("Password generated.");
    } catch (err) {
      setError(readableError(err));
    }
  }

  async function copyPassword(password: string) {
    clearMessages();
    try {
      await writeText(password);
      if (clipboardTimer.current) window.clearTimeout(clipboardTimer.current);
      clipboardTimer.current = window.setTimeout(() => {
        void clearClipboard(password);
      }, 30_000);
      setInfo("Password copied. Clipboard will clear in 30 seconds.");
    } catch (err) {
      setError(readableError(err));
    }
  }

  async function exportVault() {
    clearMessages();
    try {
      const encrypted = await invoke<string>("export_encrypted_data");
      const blob = new Blob([encrypted], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `password-manager-export-${Date.now()}.json`;
      link.click();
      URL.revokeObjectURL(url);
      setInfo("Encrypted vault exported.");
    } catch (err) {
      setError(readableError(err));
    }
  }

  async function onImportFile(event: ChangeEvent<HTMLInputElement>) {
    clearMessages();
    const file = event.currentTarget.files?.[0];
    if (!file) return;
    try {
      setImportPayload(await file.text());
      setImportFileName(file.name);
      setInfo(`Loaded file: ${file.name}`);
    } catch {
      setError("Failed to read import file.");
    }
  }

  async function importVault() {
    clearMessages();
    if (!importPayload) {
      setError("Choose an encrypted export file first.");
      return;
    }
    if (!importMasterPassword) {
      setError("Enter the imported vault master password.");
      return;
    }
    if (!window.confirm("Import replaces your local vault file. Continue?")) return;

    try {
      const rows = await invoke<unknown>("import_encrypted_data", {
        encryptedJson: importPayload,
        masterPassword: importMasterPassword,
      });
      setEntries(normalizeEntries(rows));
      setStatus({ initialized: true, unlocked: true });
      setImportPayload("");
      setImportFileName("");
      setImportMasterPassword("");
      setInfo("Encrypted vault imported.");
    } catch (err) {
      setError(readableError(err));
    }
  }

  if (!status) {
    return <main className="min-h-screen p-8">Loading...</main>;
  }

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_20%_10%,rgba(20,184,166,0.2),transparent_40%),radial-gradient(circle_at_90%_10%,rgba(234,179,8,0.2),transparent_45%)] bg-slate-100 px-4 py-6 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      <div className="mx-auto max-w-7xl">
        <header className="mb-6 flex items-center justify-between rounded-xl border border-slate-300 bg-white/75 px-4 py-3 backdrop-blur dark:border-slate-800 dark:bg-slate-900/70">
          <div>
            <h1 className="text-2xl font-bold">Password Manager</h1>
            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Tauri v2 / Rust</p>
          </div>
          <button
            type="button"
            onClick={() => setTheme((current) => (current === "dark" ? "light" : "dark"))}
            className="rounded-lg border border-slate-300 px-3 py-2 text-sm font-semibold hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800"
          >
            Theme: {theme}
          </button>
        </header>

        {error && <p className="mb-4 rounded-lg bg-rose-100 px-3 py-2 text-rose-800 dark:bg-rose-950/50 dark:text-rose-300">{error}</p>}
        {info && <p className="mb-4 rounded-lg bg-emerald-100 px-3 py-2 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300">{info}</p>}

        {!status.initialized && (
          <AuthCard
            title="Create Master Password"
            hint="Minimum 12 characters. Master password is never stored in plaintext."
            password={masterPassword}
            setPassword={setMasterPassword}
            confirm={masterConfirm}
            setConfirm={setMasterConfirm}
            submitLabel="Create Vault"
            onSubmit={setupVault}
          />
        )}

        {status.initialized && !status.unlocked && (
          <AuthCard
            title="Unlock Vault"
            hint="Enter your master password to decrypt your local vault."
            password={masterPassword}
            setPassword={setMasterPassword}
            submitLabel="Unlock"
            onSubmit={unlockVault}
          />
        )}

        {status.unlocked && (
          <section className="grid gap-4 lg:grid-cols-[1.35fr_1fr]">
            <div className="rounded-xl border border-slate-300 bg-white/80 p-4 dark:border-slate-800 dark:bg-slate-900/70">
              <div className="mb-4 grid gap-3 sm:grid-cols-2">
                <input
                  value={search}
                  onChange={(event) => setSearch(event.currentTarget.value)}
                  placeholder="Search entries..."
                  className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-950"
                />
                <select
                  value={sort}
                  onChange={(event) => setSort(event.currentTarget.value as SortMode)}
                  className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-950"
                >
                  <option value="updatedDesc">Updated (newest)</option>
                  <option value="serviceAsc">Service A-Z</option>
                  <option value="serviceDesc">Service Z-A</option>
                </select>
              </div>

              <div className="space-y-3">
                {visibleEntries.length === 0 && <p className="text-sm text-slate-500">No entries found.</p>}
                {visibleEntries.map((entry) => (
                  <article key={entry.id} className="rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-700 dark:bg-slate-900">
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div>
                        <h3 className="font-semibold">{entry.service}</h3>
                        <p className="text-sm text-slate-600 dark:text-slate-300">{entry.username || "(no username)"}</p>
                        {entry.url && <p className="text-xs text-slate-500">{entry.url}</p>}
                        <p className="text-xs text-slate-400">Updated {formatTimestamp(entry.updatedAt)}</p>
                      </div>
                      <div className="flex gap-2">
                        <button type="button" onClick={() => setRevealed((current) => ({ ...current, [entry.id]: !current[entry.id] }))} className="btn-secondary">{revealed[entry.id] ? "Hide" : "Reveal"}</button>
                        <button type="button" onClick={() => void copyPassword(entry.password)} className="btn-secondary">Copy</button>
                        <button type="button" onClick={() => { setEditingId(entry.id); setForm({ service: entry.service, username: entry.username, password: entry.password, notes: entry.notes, url: entry.url }); }} className="btn-secondary">Edit</button>
                        <button type="button" onClick={() => void deleteEntry(entry.id)} className="btn-danger">Delete</button>
                      </div>
                    </div>
                    <p className="mt-2 rounded bg-slate-100 px-2 py-1 font-mono text-sm dark:bg-slate-800">{revealed[entry.id] ? entry.password : "***************"}</p>
                    {entry.notes && <p className="mt-2 whitespace-pre-wrap text-sm text-slate-600 dark:text-slate-300">{entry.notes}</p>}
                  </article>
                ))}
              </div>
            </div>

            <div className="space-y-4">
              <section className="rounded-xl border border-slate-300 bg-white/80 p-4 dark:border-slate-800 dark:bg-slate-900/70">
                <h2 className="mb-3 text-lg font-semibold">{editingId ? "Edit Entry" : "Add Entry"}</h2>
                <form className="space-y-2" onSubmit={saveEntry}>
                  <input required value={form.service} onChange={(event) => setForm((current) => ({ ...current, service: event.currentTarget.value }))} placeholder="Service" className="input" />
                  <input value={form.username} onChange={(event) => setForm((current) => ({ ...current, username: event.currentTarget.value }))} placeholder="Username" className="input" />
                  <input required type="password" autoComplete="off" value={form.password} onChange={(event) => setForm((current) => ({ ...current, password: event.currentTarget.value }))} placeholder="Password" className="input" />
                  <input type="url" value={form.url} onChange={(event) => setForm((current) => ({ ...current, url: event.currentTarget.value }))} placeholder="URL" className="input" />
                  <textarea rows={3} value={form.notes} onChange={(event) => setForm((current) => ({ ...current, notes: event.currentTarget.value }))} placeholder="Notes" className="input" />
                  <div className="flex gap-2">
                    <button type="submit" className="btn-primary flex-1">{editingId ? "Save" : "Add"}</button>
                    <button type="button" onClick={resetForm} className="btn-secondary">Clear</button>
                  </div>
                </form>
              </section>

              <section className="rounded-xl border border-slate-300 bg-white/80 p-4 dark:border-slate-800 dark:bg-slate-900/70">
                <h2 className="mb-2 text-lg font-semibold">Generator</h2>
                <label className="text-sm">Length: {generator.length}</label>
                <input type="range" min={12} max={24} value={generator.length} onChange={(event) => setGenerator((current) => ({ ...current, length: Number(event.currentTarget.value) }))} className="mb-2 w-full" />
                <label className="mb-1 flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={generator.includeNumbers} onChange={(event) => setGenerator((current) => ({ ...current, includeNumbers: event.currentTarget.checked }))} />
                  Include numbers
                </label>
                <label className="mb-2 flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={generator.includeSymbols} onChange={(event) => setGenerator((current) => ({ ...current, includeSymbols: event.currentTarget.checked }))} />
                  Include symbols
                </label>
                <button type="button" onClick={() => void generatePassword()} className="btn-secondary w-full">Generate and fill password</button>
              </section>

              <section className="rounded-xl border border-slate-300 bg-white/80 p-4 dark:border-slate-800 dark:bg-slate-900/70">
                <h2 className="mb-2 text-lg font-semibold">Export / Import</h2>
                <button type="button" onClick={() => void exportVault()} className="btn-secondary mb-2 w-full">Export encrypted vault</button>
                <input type="file" accept=".json,application/json" onChange={(event) => void onImportFile(event)} className="input mb-2" />
                {importFileName && <p className="mb-2 text-xs text-slate-500">Selected: {importFileName}</p>}
                <input type="password" value={importMasterPassword} onChange={(event) => setImportMasterPassword(event.currentTarget.value)} placeholder="Master password for imported file" className="input mb-2" />
                <button type="button" onClick={() => void importVault()} className="btn-warning w-full">Import and replace local vault</button>
              </section>

              <button type="button" onClick={() => void lockVault("Vault locked.")} className="btn-danger w-full">Lock now</button>
            </div>
          </section>
        )}
      </div>
    </main>
  );
}

interface AuthCardProps {
  title: string;
  hint: string;
  password: string;
  setPassword: (value: string) => void;
  submitLabel: string;
  onSubmit: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  confirm?: string;
  setConfirm?: (value: string) => void;
}

function AuthCard(props: AuthCardProps) {
  return (
    <section className="mx-auto mt-8 max-w-lg rounded-xl border border-slate-300 bg-white/80 p-6 dark:border-slate-800 dark:bg-slate-900/70">
      <h2 className="text-xl font-semibold">{props.title}</h2>
      <p className="mb-4 mt-1 text-sm text-slate-500">{props.hint}</p>
      <form className="space-y-3" onSubmit={(event) => void props.onSubmit(event)}>
        <input
          type="password"
          required
          autoComplete={props.confirm !== undefined ? "new-password" : "current-password"}
          value={props.password}
          onChange={(event) => props.setPassword(event.currentTarget.value)}
          placeholder="Master password"
          className="input"
        />
        {props.confirm !== undefined && props.setConfirm !== undefined && (
          <input
            type="password"
            required
            autoComplete="new-password"
            value={props.confirm}
            onChange={(event) => props.setConfirm?.(event.currentTarget.value)}
            placeholder="Confirm master password"
            className="input"
          />
        )}
        <button type="submit" className="btn-primary w-full">
          {props.submitLabel}
        </button>
      </form>
    </section>
  );
}

async function clearClipboard(expected: string) {
  try {
    if ((await readText()) === expected) await writeText("");
  } catch {
    // best effort
  }
}

function formatTimestamp(timestamp: number): string {
  if (!timestamp) return "Unknown";
  return new Date(timestamp * 1000).toLocaleString();
}

function normalizeEntries(payload: unknown): PasswordEntry[] {
  if (!Array.isArray(payload)) return [];
  return payload.map((entry) => normalizeEntry(entry)).filter((entry): entry is PasswordEntry => entry !== null);
}

function normalizeEntry(payload: unknown): PasswordEntry | null {
  if (!payload || typeof payload !== "object") return null;
  const raw = payload as Record<string, unknown>;

  const id = normalizeString(raw.id);
  const service = normalizeString(raw.service);
  const password = normalizeString(raw.password);
  if (!id || !service || !password) return null;

  return {
    id,
    service,
    username: normalizeString(raw.username),
    password,
    notes: normalizeString(raw.notes),
    url: normalizeString(raw.url),
    createdAt: normalizeTimestamp(raw.createdAt ?? raw.created_at),
    updatedAt: normalizeTimestamp(raw.updatedAt ?? raw.updated_at),
  };
}

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function normalizeTimestamp(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return 0;
}

function readableError(error: unknown): string {
  if (typeof error === "string") return error;
  if (error && typeof error === "object" && "toString" in error) return String(error);
  return "Unexpected error.";
}

export default App;
