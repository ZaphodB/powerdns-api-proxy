"""Role names assigned to static environments via environment_roles
(settings.py). Constants so a typo fails loudly at import instead of silently
never matching a membership test."""

ADMIN = "admin"
EXPORTER = "exporter"
WEBUI = "webui"
METRICS = "metrics"
REGISTRAR = "registrar"

# Validated against at config load (settings.environment_roles). The constants
# above only protect code; this protects the CONFIG, where an unrecognised role
# name is a typo that silently removes a restriction rather than failing.
KNOWN_ROLES = frozenset({ADMIN, EXPORTER, WEBUI, METRICS, REGISTRAR})
