import re
from pathlib import Path

import yaml

from app.analysis.criticality import from_severity, raise_floor

KNOWLEDGE = Path(__file__).resolve().parent.parent / "knowledge" / "signatures.yaml"

GENERIC = {
    "critico": {
        "title": "Evento crítico",
        "explanation": "El equipo marcó este evento con la severidad más alta. Puede haber caída de servicio, fallo grave o un incidente de seguridad.",
        "probable_cause": "Fallo de plataforma, pérdida de un enlace principal o un evento de seguridad grave.",
        "actions": [
            "Abre el mensaje crudo y comprueba si el servicio o el enlace sigue afectado.",
            "Revisa el estado actual del dispositivo y los eventos vecinos en la línea de tiempo.",
            "Si el impacto continúa, escala al responsable de red o de seguridad.",
        ],
    },
    "alto": {
        "title": "Evento de severidad alta",
        "explanation": "El equipo reportó un error o una condición que ya afecta a un servicio, un enlace o la seguridad.",
        "probable_cause": "Un fallo concreto del dispositivo, una denegación relevante o una autenticación rechazada.",
        "actions": [
            "Lee el mensaje y anota interfaz, usuario o direcciones que aparezcan.",
            "Comprueba si la condición sigue activa o si ya hay un evento de recuperación.",
            "Actúa sobre el elemento afectado antes de tratarlo como ruido.",
        ],
    },
    "medio": {
        "title": "Aviso",
        "explanation": "Hay una condición anómala que todavía no implica, por sí sola, una caída total.",
        "probable_cause": "Una política que deniega tráfico, un aviso del equipo o un cambio que conviene verificar.",
        "actions": [
            "Revisa si el mensaje encaja con un cambio o una política previstos.",
            "Si se repite mucho en poco tiempo, míralo junto con los eventos del mismo dispositivo.",
        ],
    },
    "bajo": {
        "title": "Aviso menor",
        "explanation": "El equipo informó de un cambio de estado o de un hecho de poca urgencia.",
        "probable_cause": "Un evento operativo normal o una notificación de seguimiento.",
        "actions": [
            "Úsalo como contexto de lo que pasó alrededor de los eventos más graves.",
            "No requiere acción si el estado final del servicio es el esperado.",
        ],
    },
    "informativo": {
        "title": "Evento informativo",
        "explanation": "Registro de actividad normal o de depuración. Sirve de contexto, no como alarma.",
        "probable_cause": "Tráfico permitido, un inicio de sesión correcto o un mensaje de diagnóstico.",
        "actions": [
            "Consúltalo solo si estás reconstruyendo qué pasó en ese minuto.",
            "No requiere acción por sí mismo.",
        ],
    },
}

_CACHE = {"mtime": None, "items": []}


def load_signatures():
    mtime = KNOWLEDGE.stat().st_mtime
    if _CACHE["mtime"] == mtime:
        return _CACHE["items"]
    with KNOWLEDGE.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    items = []
    for item in data.get("signatures") or []:
        if item.get("id") and item.get("title") and item.get("explanation") and item.get("actions"):
            items.append(item)
    _CACHE["mtime"] = mtime
    _CACHE["items"] = items
    return items


def _contains(haystack, needle):
    return needle.lower() in (haystack or "").lower()


def _matches(signature, event):
    fields = event.get("fields") or {}
    if signature.get("vendor") and signature["vendor"] != event.get("vendor"):
        return False
    if signature.get("mnemonic") and signature["mnemonic"] != (event.get("mnemonic") or ""):
        return False
    if signature.get("mnemonic_regex") and not re.search(signature["mnemonic_regex"], event.get("mnemonic") or ""):
        return False
    if signature.get("logid") and str(signature["logid"]) != str(fields.get("logid", "")):
        return False
    if signature.get("type") and signature["type"].lower() != str(fields.get("type", "")).lower():
        return False
    if signature.get("subtype") and signature["subtype"].lower() != str(fields.get("subtype", "")).lower():
        return False
    if signature.get("action") and str(signature["action"]).lower() != str(fields.get("action", "")).lower():
        return False
    action = str(fields.get("action") or "")
    denied = [str(item).lower() for item in signature.get("action_not") or []]
    if denied and action.lower() in denied:
        return False
    blob = "%s %s" % (event.get("message") or "", event.get("raw") or "")
    if signature.get("message_contains") and not _contains(blob, signature["message_contains"]):
        return False
    if signature.get("message_not_contains") and _contains(blob, signature["message_not_contains"]):
        return False
    if signature.get("message_regex") and not re.search(signature["message_regex"], blob):
        return False
    if signature.get("message_not_regex") and re.search(signature["message_not_regex"], blob):
        return False
    for key, needle in (signature.get("field_contains") or {}).items():
        if not _contains(str(fields.get(key, "")), str(needle)):
            return False
    for key, expected in (signature.get("field_equals") or {}).items():
        if str(fields.get(key, "")).lower() != str(expected).lower():
            return False
    return True


def match_signature(event):
    if event.get("unparsed"):
        return None
    for signature in load_signatures():
        if _matches(signature, event):
            return signature
    return None


def _fallback_title(event, generic_title):
    if event.get("mnemonic"):
        return event["mnemonic"]
    fields = event.get("fields") or {}
    kind = fields.get("type")
    if kind:
        subtype = fields.get("subtype")
        return "%s/%s" % (kind, subtype) if subtype else kind
    return generic_title


def apply_rules(event):
    base = from_severity(event.get("severity_num"))
    if event.get("unparsed"):
        event["criticality"] = base
        event["title"] = "Línea no reconocida"
        event["explanation"] = (
            "Esta línea no coincide con Cisco IOS/ASA ni con FortiGate en clave=valor. "
            "Se conserva para no perderla."
        )
        if event.get("severity_num") is not None:
            event["explanation"] += " La cabecera syslog trae severidad %s." % (event.get("severity_original") or event["severity_num"])
        event["probable_cause"] = "Formato distinto, mensaje truncado o un tipo de log que esta versión aún no reconoce."
        event["actions"] = [
            "Comprueba que el export incluye la línea completa.",
            "Si venía con cabecera syslog, la criticidad sale de esa severidad.",
        ]
        event["signature_id"] = None
        return event

    signature = match_signature(event)
    if signature:
        event["criticality"] = raise_floor(base, signature.get("criticality_floor") or base)
        event["title"] = signature["title"]
        event["explanation"] = signature["explanation"]
        event["probable_cause"] = signature.get("probable_cause") or GENERIC[event["criticality"]]["probable_cause"]
        event["actions"] = [str(item) for item in signature["actions"]]
        event["signature_id"] = signature["id"]
        return event

    generic = GENERIC[base]
    event["criticality"] = base
    event["title"] = _fallback_title(event, generic["title"])
    event["explanation"] = generic["explanation"]
    event["probable_cause"] = generic["probable_cause"]
    event["actions"] = list(generic["actions"])
    event["signature_id"] = None
    return event
