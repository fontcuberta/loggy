import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { CRITICALITY, VENDORS, ZONES, api, formatTime, vendorLabel } from "./api";

const EMPTY_FILTERS = {
  criticality: "",
  vendor: "",
  device: "",
  order: "desc",
  from_local: "",
  to_local: "",
};

export default function App() {
  const [settings, setSettings] = useState(null);
  const [draft, setDraft] = useState(null);
  const [syslog, setSyslog] = useState(null);
  const [ollama, setOllama] = useState(null);
  const [devices, setDevices] = useState([]);
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [query, setQuery] = useState("");
  const [q, setQ] = useState("");
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [summary, setSummary] = useState({ total: 0, by_criticality: {} });
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [notice, setNotice] = useState("");
  const [banner, setBanner] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const fileRef = useRef(null);
  const atHead = useRef(true);
  const parentRef = useRef(null);

  useEffect(() => {
    const timer = setTimeout(() => setQ(query.trim()), 300);
    return () => clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    let stop = false;
    api.settings().then((data) => {
      if (!stop) setSettings(data);
    }).catch((error) => setBanner(error.message));
    refreshOllama();
    return () => {
      stop = true;
    };
  }, []);

  useEffect(() => {
    let last = -1;
    let stop = false;
    async function tick() {
      try {
        const status = await api.syslog();
        if (stop) return;
        setSyslog(status);
        if (last >= 0 && status.received > last && atHead.current) {
          setReloadKey((value) => value + 1);
        }
        last = status.received;
      } catch (error) {
        if (!stop) setBanner(error.message);
      }
    }
    tick();
    const timer = setInterval(tick, 4000);
    return () => {
      stop = true;
      clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    let stop = false;
    async function load() {
      setLoading(true);
      atHead.current = true;
      const params = currentParams();
      const countsParams = { ...params, criticality: "" };
      try {
        const [page, counts, names] = await Promise.all([
          api.events({ ...params, limit: 200, offset: 0 }),
          api.summary(countsParams),
          api.devices(),
        ]);
        if (stop) return;
        setEvents(page.events);
        setTotal(page.total);
        setSummary(counts);
        setDevices(names.devices);
        setBanner("");
      } catch (error) {
        if (!stop) setBanner(error.message);
      } finally {
        if (!stop) setLoading(false);
      }
    }
    load();
    return () => {
      stop = true;
    };
  }, [filters, q, reloadKey]);

  useEffect(() => {
    function onKey(event) {
      if (event.key !== "Escape") return;
      if (settingsOpen) setSettingsOpen(false);
      else setDetail(null);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [settingsOpen]);

  const zones = useMemo(() => {
    const current = settings?.timezone;
    if (current && !ZONES.includes(current)) return [current, ...ZONES];
    return ZONES;
  }, [settings]);

  const virtualizer = useVirtualizer({
    count: events.length + (events.length < total ? 1 : 0),
    getScrollElement: () => parentRef.current,
    estimateSize: () => 92,
    overscan: 8,
  });

  function currentParams() {
    return {
      criticality: filters.criticality,
      vendor: filters.vendor,
      device: filters.device,
      q,
      order: filters.order,
      from_local: filters.from_local,
      to_local: filters.to_local,
    };
  }

  async function refreshOllama() {
    try {
      setOllama(await api.ollama());
    } catch (error) {
      setOllama({ ok: false, error: error.message, models: [] });
    }
  }

  async function loadMore() {
    atHead.current = false;
    const page = await api.events({ ...currentParams(), limit: 200, offset: events.length });
    setEvents((current) => current.concat(page.events));
    setTotal(page.total);
  }

  async function onFiles(fileList) {
    const files = Array.from(fileList || []);
    if (!files.length) return;
    setUploading(true);
    setNotice("");
    try {
      const result = await api.upload(files);
      setNotice(
        `${result.accepted} líneas de ${result.files.length} archivo${result.files.length === 1 ? "" : "s"}. ${result.unparsed} sin reconocer.`
      );
      setReloadKey((value) => value + 1);
    } catch (error) {
      setBanner(error.message);
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  async function openEvent(id, refresh = false) {
    setDetailLoading(true);
    setBanner("");
    if (!refresh) {
      setDetail((current) => (current && current.id === id ? current : null));
    }
    try {
      const data = await api.event(id, refresh);
      setDetail(data);
      setEvents((current) =>
        current.map((item) =>
          item.id === id ? { ...item, llm_enhanced: data.llm_enhanced, engine_used: data.engine_used, title: data.title } : item
        )
      );
    } catch (error) {
      setBanner(error.message);
    } finally {
      setDetailLoading(false);
    }
  }

  function openSettings() {
    setDraft({
      engine: settings.engine,
      ollama_url: settings.ollama_url,
      ollama_model: settings.ollama_model,
      timezone: settings.timezone,
      syslog_port: Number(settings.syslog_port),
      syslog_enabled: settings.syslog_enabled === "true",
    });
    setSettingsOpen(true);
    refreshOllama();
  }

  async function saveSettings(event) {
    event.preventDefault();
    try {
      const result = await api.saveSettings(draft);
      setSettings(result.settings);
      setSyslog(result.syslog);
      setSettingsOpen(false);
      setReloadKey((value) => value + 1);
      refreshOllama();
    } catch (error) {
      setBanner(error.message);
    }
  }

  async function purge() {
    if (!window.confirm("Se borrarán todos los eventos guardados en este equipo.")) return;
    await api.purge();
    setDetail(null);
    setNotice("Datos locales borrados.");
    setReloadKey((value) => value + 1);
  }

  const engine = settings?.engine || "hybrid";
  const timeZone = settings?.timezone || "UTC";

  return (
    <div className="app">
      <header className="top">
        <div>
          <p className="brand">Loggy</p>
          <h1>Analizador de logs Cisco y FortiGate</h1>
        </div>
        <div className="top-actions">
          <span className="private">En este equipo</span>
          <button type="button" onClick={openSettings} disabled={!settings}>
            Ajustes
          </button>
        </div>
      </header>

      {banner ? <p className="banner">{banner}</p> : null}
      {engine !== "rules" && ollama && !ollama.ok ? (
        <p className="banner quiet">{ollama.error}</p>
      ) : null}

      <section className="ingest">
        <div
          className={dragOver ? "drop drag" : "drop"}
          onDragOver={(event) => {
            event.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDragOver(false);
            onFiles(event.dataTransfer.files);
          }}
        >
          <strong>Suelta archivos .log o .txt</strong>
          <p>Puedes cargar varios a la vez. Se ordenan por tiempo y no salen del equipo.</p>
          <button type="button" onClick={() => fileRef.current?.click()} disabled={uploading}>
            {uploading ? "Analizando…" : "Elegir archivos"}
          </button>
          <input
            ref={fileRef}
            type="file"
            multiple
            hidden
            onChange={(event) => onFiles(event.target.files)}
          />
          {notice ? <p className="notice">{notice}</p> : null}
        </div>
        <SyslogCard syslog={syslog} />
      </section>

      <section className="filters">
        <label>
          Criticidad
          <select
            value={filters.criticality}
            onChange={(event) => setFilters({ ...filters, criticality: event.target.value })}
          >
            <option value="">Todas</option>
            {CRITICALITY.map(([value, name]) => (
              <option key={value} value={value}>
                {name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Fabricante
          <select value={filters.vendor} onChange={(event) => setFilters({ ...filters, vendor: event.target.value })}>
            <option value="">Todos</option>
            {VENDORS.map(([value, name]) => (
              <option key={value} value={value}>
                {name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Dispositivo
          <select value={filters.device} onChange={(event) => setFilters({ ...filters, device: event.target.value })}>
            <option value="">Todos</option>
            {devices.map((device) => (
              <option key={device} value={device}>
                {device}
              </option>
            ))}
          </select>
        </label>
        <label>
          Desde
          <input
            type="datetime-local"
            value={filters.from_local}
            onChange={(event) => setFilters({ ...filters, from_local: event.target.value })}
          />
        </label>
        <label>
          Hasta
          <input
            type="datetime-local"
            value={filters.to_local}
            onChange={(event) => setFilters({ ...filters, to_local: event.target.value })}
          />
        </label>
        <label className="grow">
          Buscar
          <input
            type="search"
            value={query}
            placeholder="Mensaje, código, dispositivo"
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
        <button
          type="button"
          className="ghost"
          onClick={() => setFilters({ ...filters, order: filters.order === "desc" ? "asc" : "desc" })}
        >
          {filters.order === "desc" ? "Recientes primero" : "Antiguos primero"}
        </button>
      </section>

      <div className="counts">
        <button type="button" className={!filters.criticality ? "on" : ""} onClick={() => setFilters({ ...filters, criticality: "" })}>
          {summary.total} {summary.total === 1 ? "evento" : "eventos"}
        </button>
        {CRITICALITY.map(([value, name]) => (
          <button
            key={value}
            type="button"
            className={filters.criticality === value ? `on ${value}` : value}
            onClick={() => setFilters({ ...filters, criticality: filters.criticality === value ? "" : value })}
          >
            {summary.by_criticality?.[value] || 0} {name}
          </button>
        ))}
      </div>

      <div className={detail ? "workspace open" : "workspace"}>
        <div className="timeline" ref={parentRef}>
          {loading && events.length === 0 ? <p className="empty">Cargando eventos…</p> : null}
          {!loading && events.length === 0 ? (
            <p className="empty">Todavía no hay eventos con estos filtros. Carga un archivo o envía syslog a localhost.</p>
          ) : null}
            <div style={{ height: virtualizer.getTotalSize(), position: "relative", width: "100%" }}>
            {virtualizer.getVirtualItems().map((item) => {
              if (item.index >= events.length) {
                return (
                  <div
                    key="more"
                    className="more"
                    style={{ transform: `translateY(${item.start}px)` }}
                    ref={virtualizer.measureElement}
                    data-index={item.index}
                  >
                    <button type="button" onClick={loadMore}>
                      Cargar más
                    </button>
                  </div>
                );
              }
              const event = events[item.index];
              return (
                <article
                  key={event.id}
                  data-index={item.index}
                  ref={virtualizer.measureElement}
                  className={detail?.id === event.id ? `row ${event.criticality} selected` : `row ${event.criticality}`}
                  style={{ transform: `translateY(${item.start}px)` }}
                >
                  <button type="button" onClick={() => openEvent(event.id)}>
                    <span className="meta">
                      <span className={`pill ${event.criticality}`}>{event.criticality_label}</span>
                      <time dateTime={event.timestamp}>{formatTime(event.timestamp, timeZone)}</time>
                      {event.timestamp_estimated ? <span className="flag">tiempo estimado</span> : null}
                      <span>{event.device}</span>
                      <span>{vendorLabel(event.vendor)}</span>
                      {event.llm_enhanced ? <span className="flag">modelo local</span> : null}
                    </span>
                    <strong>{event.title}</strong>
                    <p>{event.message}</p>
                  </button>
                </article>
              );
            })}
          </div>
        </div>
        {detail || detailLoading ? (
          <Detail
            detail={detail}
            loading={detailLoading}
            timeZone={timeZone}
            engine={engine}
            onClose={() => setDetail(null)}
            onRefresh={() => detail && openEvent(detail.id, true)}
          />
        ) : null}
      </div>

      {settingsOpen && draft ? (
        <div className="modal-back" onMouseDown={() => setSettingsOpen(false)}>
          <form className="modal" onMouseDown={(event) => event.stopPropagation()} onSubmit={saveSettings}>
            <h2>Ajustes</h2>
            <fieldset>
              <legend>Motor</legend>
              <label className="choice">
                <input
                  type="radio"
                  name="engine"
                  checked={draft.engine === "rules"}
                  onChange={() => setDraft({ ...draft, engine: "rules" })}
                />
                <span>
                  <strong>Reglas locales</strong>
                  Criticidad y acciones de la base del equipo. No usa ningún modelo.
                </span>
              </label>
              <label className="choice">
                <input
                  type="radio"
                  name="engine"
                  checked={draft.engine === "llm"}
                  onChange={() => setDraft({ ...draft, engine: "llm" })}
                />
                <span>
                  <strong>Modelo local</strong>
                  Ollama redacta la explicación y las acciones. La criticidad la siguen fijando las reglas.
                </span>
              </label>
              <label className="choice">
                <input
                  type="radio"
                  name="engine"
                  checked={draft.engine === "hybrid"}
                  onChange={() => setDraft({ ...draft, engine: "hybrid" })}
                />
                <span>
                  <strong>Híbrido</strong>
                  Las reglas deciden criticidad y acciones, y Ollama amplía el texto. Si no responde, te quedas con las reglas.
                </span>
              </label>
            </fieldset>
            <label>
              URL de Ollama
              <input
                value={draft.ollama_url}
                onChange={(event) => setDraft({ ...draft, ollama_url: event.target.value })}
              />
            </label>
            <p className="hint">Solo se acepta localhost. Una dirección externa se rechaza.</p>
            <label>
              Modelo
              <input
                value={draft.ollama_model}
                onChange={(event) => setDraft({ ...draft, ollama_model: event.target.value })}
              />
            </label>
            <p className="hint">
              {ollama?.ok
                ? `Ollama responde. Modelos: ${ollama.models.length ? ollama.models.join(", ") : "ninguno descargado"}.`
                : ollama?.error}
            </p>
            <label>
              Zona horaria de los logs sin zona
              <select value={draft.timezone} onChange={(event) => setDraft({ ...draft, timezone: event.target.value })}>
                {zones.map((zone) => (
                  <option key={zone} value={zone}>
                    {zone}
                  </option>
                ))}
              </select>
            </label>
            <p className="hint">Se aplica a logs nuevos. Los que ya están guardados no se recalculan.</p>
            <label className="inline">
              <input
                type="checkbox"
                checked={draft.syslog_enabled}
                onChange={(event) => setDraft({ ...draft, syslog_enabled: event.target.checked })}
              />
              Recibir syslog en localhost
            </label>
            <label>
              Puerto syslog
              <input
                type="number"
                min="1"
                max="65535"
                value={draft.syslog_port}
                onChange={(event) => setDraft({ ...draft, syslog_port: Number(event.target.value) })}
              />
            </label>
            <p className="hint">El 514 en macOS pide privilegios. 5514 no.</p>
            <div className="modal-actions">
              <button type="button" className="danger" onClick={purge}>
                Borrar datos locales
              </button>
              <span className="spacer" />
              <button type="button" className="ghost" onClick={() => setSettingsOpen(false)}>
                Cancelar
              </button>
              <button type="submit">Guardar</button>
            </div>
          </form>
        </div>
      ) : null}
    </div>
  );
}

function SyslogCard({ syslog }) {
  if (!syslog) return <aside className="syslog">Comprobando syslog…</aside>;
  return (
    <aside className="syslog">
      <h2>Syslog</h2>
      {syslog.running ? (
        <p>
          Escuchando en {syslog.host}:{syslog.port} por UDP y TCP.
        </p>
      ) : (
        <p>{syslog.enabled ? "El receptor no está activo." : "Recepción en vivo desactivada."}</p>
      )}
      {syslog.error ? <p className="warn">{syslog.error}</p> : null}
      <p className="stat">{syslog.received} líneas recibidas en esta sesión</p>
    </aside>
  );
}

function Detail({ detail, loading, timeZone, engine, onClose, onRefresh }) {
  const fields = detail?.fields || {};
  const preferred = ["srcip", "srcport", "dstip", "dstport", "action", "policyid", "user", "interface", "type", "subtype", "level", "logid"];
  const keys = Object.keys(fields).filter((key) => key !== "msg");
  keys.sort((a, b) => {
    const left = preferred.indexOf(a);
    const right = preferred.indexOf(b);
    if (left === -1 && right === -1) return a.localeCompare(b);
    if (left === -1) return 1;
    if (right === -1) return -1;
    return left - right;
  });
  return (
    <aside className="detail">
      <div className="detail-head">
        <h2>{detail?.title || "Evento"}</h2>
        <button type="button" className="ghost" onClick={onClose}>
          Cerrar
        </button>
      </div>
      {loading ? <p className="hint">{engine === "rules" ? "Abriendo evento…" : "Consultando el modelo local…"}</p> : null}
      {detail ? (
        <>
          <p className="meta">
            <span className={`pill ${detail.criticality}`}>{detail.criticality_label}</span>
            <time dateTime={detail.timestamp}>{formatTime(detail.timestamp, timeZone)}</time>
          </p>
          <p className="who">
            {detail.device} · {vendorLabel(detail.vendor)}
            {detail.severity_original ? ` · severidad ${detail.severity_original}` : ""}
            {detail.mnemonic ? ` · ${detail.mnemonic}` : ""}
          </p>
          <p className="who">
            {detail.source === "syslog" ? "Recibido por syslog" : `Archivo ${detail.source_name}`}
            {detail.timestamp_estimated ? " · año o reloj estimado" : ""}
            {detail.tz_assumed ? " · zona horaria supuesta" : ""}
            {detail.unparsed ? " · formato no reconocido" : ""}
          </p>
          {detail.llm_error && engine !== "rules" ? <p className="warn">{detail.llm_error}</p> : null}
          <h3>Qué pasa</h3>
          <p>{detail.explanation}</p>
          <h3>Causa probable</h3>
          <p>{detail.probable_cause}</p>
          <h3>Qué hacer</h3>
          <ol>
            {detail.actions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ol>
          {engine !== "rules" ? (
            <button type="button" className="ghost" onClick={onRefresh} disabled={loading}>
              Volver a analizar con el modelo local
            </button>
          ) : null}
          <p className="hint">
            {`Texto de ${
              detail.engine_used === "rules"
                ? "reglas locales"
                : detail.engine_used === "hybrid"
                  ? "reglas ampliadas por el modelo local"
                  : "modelo local"
            }. La criticidad no la cambia el modelo.${detail.signature_id ? ` Firma ${detail.signature_id}.` : ""}`}
          </p>
          {keys.length ? (
            <>
              <h3>Campos</h3>
              <dl>
                {keys.map((key) => (
                  <div key={key}>
                    <dt>{key}</dt>
                    <dd>{String(fields[key])}</dd>
                  </div>
                ))}
              </dl>
            </>
          ) : null}
          <h3>Línea original</h3>
          <pre>{detail.raw}</pre>
        </>
      ) : null}
    </aside>
  );
}
