async function request(path, options) {
  const response = await fetch(path, options);
  const text = await response.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch (error) {
      body = { detail: text };
    }
  }
  if (!response.ok) {
    const detail = body && (body.detail || body.error);
    throw new Error(typeof detail === "string" ? detail : "No se pudo completar la petición");
  }
  return body;
}

export function formatTime(iso, timeZone) {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return new Intl.DateTimeFormat("es", {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: timeZone || "UTC",
  }).format(date);
}

export const api = {
  settings: () => request("/api/settings"),
  saveSettings: (payload) =>
    request("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  ollama: () => request("/api/ollama"),
  syslog: () => request("/api/syslog"),
  devices: () => request("/api/devices"),
  events: (params) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== "") query.set(key, value);
    });
    return request(`/api/events?${query.toString()}`);
  },
  summary: (params) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== "") query.set(key, value);
    });
    return request(`/api/summary?${query.toString()}`);
  },
  event: (id, refresh = false) => request(`/api/events/${id}?enrich=true&refresh=${refresh ? "true" : "false"}`),
  upload: async (files) => {
    const body = new FormData();
    Array.from(files).forEach((file) => body.append("files", file));
    return request("/api/upload", { method: "POST", body });
  },
  purge: () => request("/api/purge", { method: "POST" }),
};

export const CRITICALITY = [
  ["critico", "Crítico"],
  ["alto", "Alto"],
  ["medio", "Medio"],
  ["bajo", "Bajo"],
  ["informativo", "Informativo"],
];

export const VENDORS = [
  ["cisco", "Cisco"],
  ["fortigate", "FortiGate"],
  ["unknown", "Desconocido"],
];

export const ZONES = [
  "Europe/Madrid",
  "Atlantic/Canary",
  "UTC",
  "Europe/London",
  "America/Mexico_City",
  "America/Bogota",
  "America/Lima",
  "America/Santiago",
  "America/Argentina/Buenos_Aires",
  "America/New_York",
];

export function vendorLabel(vendor) {
  const found = VENDORS.find(([value]) => value === vendor);
  return found ? found[1] : vendor;
}
