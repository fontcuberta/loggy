RANK = ["informativo", "bajo", "medio", "alto", "critico"]

LABELS = {
    "critico": "Crítico",
    "alto": "Alto",
    "medio": "Medio",
    "bajo": "Bajo",
    "informativo": "Informativo",
}

SEVERITY_NAMES = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "informational",
    7: "debug",
}

FORTIGATE_LEVELS = {
    "emergency": 0,
    "alert": 1,
    "critical": 2,
    "error": 3,
    "warning": 4,
    "notice": 5,
    "notification": 5,
    "information": 6,
    "info": 6,
    "informational": 6,
    "debug": 7,
}


def from_severity(severity_num):
    if severity_num is None:
        return "informativo"
    if severity_num <= 2:
        return "critico"
    if severity_num == 3:
        return "alto"
    if severity_num == 4:
        return "medio"
    if severity_num == 5:
        return "bajo"
    return "informativo"


def raise_floor(current, floor):
    if floor not in RANK or current not in RANK:
        return current
    if RANK.index(floor) > RANK.index(current):
        return floor
    return current


def label(criticality):
    return LABELS.get(criticality, criticality)
