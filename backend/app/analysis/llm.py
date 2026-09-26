import json
from urllib.parse import urlparse

import httpx

from app.analysis.criticality import label

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
SYSTEM_PROMPT = (
    "Eres un analista de redes. Respondes solo con un JSON válido, en español, "
    "con las claves explanation, probable_cause y actions. "
    "actions es una lista corta de pasos concretos. "
    "No inventes direcciones, usuarios ni hechos que no estén en el evento. "
    "No pidas enviar los logs a ningún servicio externo. "
    "La criticidad ya está decidida y no puedes cambiarla."
)


class LocalModelError(ValueError):
    pass


def assert_local_url(url):
    parsed = urlparse((url or "").strip())
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in ("http", "https") or host not in LOCAL_HOSTS:
        raise LocalModelError("El modelo solo puede estar en localhost. Los logs no salen de este equipo.")
    if parsed.username or parsed.password:
        raise LocalModelError("La URL del modelo no puede llevar credenciales.")
    return (url or "").strip().rstrip("/")


def parse_llm_payload(text):
    raw = (text or "").strip()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start < 0 or end <= start:
            raise LocalModelError("El modelo no devolvió JSON.")
        data = json.loads(raw[start : end + 1])
    if not isinstance(data, dict):
        raise LocalModelError("El modelo no devolvió un objeto JSON.")
    explanation = str(data.get("explanation") or "").strip()
    cause = str(data.get("probable_cause") or "").strip()
    actions = data.get("actions") or []
    if isinstance(actions, str):
        actions = [actions]
    clean = []
    if isinstance(actions, list):
        for item in actions:
            step = str(item).strip()
            if step:
                clean.append(step)
    return {"explanation": explanation, "probable_cause": cause, "actions": clean[:8]}


def combine(event, llm_payload, mode):
    rule_actions = list(event.get("actions") or [])
    if mode == "hybrid":
        explanation = llm_payload["explanation"] or event.get("explanation") or ""
        cause = llm_payload["probable_cause"] or event.get("probable_cause") or ""
        actions = list(rule_actions)
        seen = set(item.lower() for item in actions)
        for extra in llm_payload["actions"]:
            if extra.lower() not in seen:
                actions.append(extra)
                seen.add(extra.lower())
        return explanation, cause, actions
    explanation = llm_payload["explanation"] or event.get("explanation") or ""
    cause = llm_payload["probable_cause"] or event.get("probable_cause") or ""
    actions = llm_payload["actions"] or rule_actions
    return explanation, cause, actions


def build_prompt(event, mode):
    fields = event.get("fields") or {}
    compact = {key: fields[key] for key in list(fields)[:40]}
    lines = [
        "Evento ya parseado. No cambies la criticidad %s." % label(event.get("criticality")),
        "Vendor: %s" % event.get("vendor"),
        "Dispositivo: %s" % event.get("device"),
        "Código: %s" % (event.get("mnemonic") or ""),
        "Título de reglas: %s" % event.get("title"),
        "Mensaje: %s" % (event.get("message") or ""),
        "Campos: %s" % json.dumps(compact, ensure_ascii=False),
        "Línea original: %s" % (event.get("raw") or "")[:4000],
    ]
    if mode == "hybrid":
        lines.append("Explicación de reglas: %s" % event.get("explanation"))
        lines.append("Causa de reglas: %s" % event.get("probable_cause"))
        lines.append("Acciones de reglas: %s" % json.dumps(event.get("actions") or [], ensure_ascii=False))
        lines.append("Amplía la explicación y la causa. Conserva las acciones de reglas y añade solo pasos que no las contradigan.")
    else:
        lines.append("Redacta la explicación, la causa probable y las acciones a partir de este evento.")
    return "\n".join(lines)


async def ollama_chat(settings, prompt):
    base = assert_local_url(settings["ollama_url"])
    url = base + "/api/chat"
    payload = {
        "model": settings["ollama_model"],
        "stream": False,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "format": "json",
        "options": {"temperature": 0.2, "num_predict": 700},
    }
    timeout = httpx.Timeout(60.0, connect=3.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        response = await client.post(url, json=payload)
        response.raise_for_status()
        if response.is_redirect:
            raise LocalModelError("Ollama no puede redirigir fuera de localhost.")
        body = response.json()
    content = ((body.get("message") or {}).get("content")) or ""
    return parse_llm_payload(content)


async def ollama_health(settings):
    try:
        base = assert_local_url(settings["ollama_url"])
    except LocalModelError as exc:
        return {"ok": False, "models": [], "error": str(exc)}
    url = base + "/api/tags"
    try:
        timeout = httpx.Timeout(3.0, connect=2.0)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
        models = []
        for item in data.get("models") or []:
            name = item.get("name")
            if name:
                models.append(name)
        return {"ok": True, "models": models, "error": None}
    except Exception:
        return {
            "ok": False,
            "models": [],
            "error": "Ollama no responde en localhost. El análisis sigue con las reglas locales.",
        }


async def enrich(event, settings, mode):
    try:
        payload = await ollama_chat(settings, build_prompt(event, mode))
        explanation, cause, actions = combine(event, payload, mode)
        if not explanation:
            raise LocalModelError("El modelo no devolvió una explicación.")
        return {
            "ok": True,
            "explanation": explanation,
            "probable_cause": cause,
            "actions": actions,
            "error": None,
        }
    except Exception:
        return {
            "ok": False,
            "error": "Ollama no respondió. Se mantienen la explicación y las acciones de las reglas.",
        }
