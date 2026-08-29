"""
garmin_mcp OAuth — Conector Garmin Connect con flujo de autorización.

Experiencia tipo Strava: agregas el conector en claude.ai, Claude te manda a
una pantalla de autorización, pones tus credenciales de Garmin UNA vez,
autorizas, y listo — sin secrets en la URL ni contraseñas en variables.

El servidor actúa como Authorization Server OAuth 2.1 (con registro dinámico
de clientes y PKCE, lo que claude.ai espera de un conector personalizado).
En la pantalla de autorización haces login con Garmin; los tokens de Garmin
se guardan en el servidor y a Claude solo se le entrega un access token
propio del conector.

Variables de entorno:
    PUBLIC_URL   URL pública del servicio, ej. https://xxxx.up.railway.app
    PORT         puerto (lo inyecta Railway/Render)
    DATA_DIR     carpeta para tokens persistidos (default /data si existe,
                 si no /tmp/garmin_mcp)

Incluye lectura del plan de TrainingPeaks vía el calendario de Garmin
(conexión TP → Garmin activada en TrainingPeaks).
"""

import html
import json
import os
import secrets
import time
from datetime import date, timedelta
from typing import Any

import uvicorn
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from pydantic import AnyUrl

from mcp.server.mcpserver import MCPServer
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

# --------------------------------------------------------------- configuración

PUBLIC_URL = (os.environ.get("PUBLIC_URL") or os.environ.get("RENDER_EXTERNAL_URL") or "http://localhost:8000").rstrip("/")
DATA_DIR = os.environ.get(
    "DATA_DIR", "/data" if os.path.isdir("/data") else "/tmp/garmin_mcp"
)
os.makedirs(DATA_DIR, exist_ok=True)
GARMIN_TOKEN_DIR = os.path.join(DATA_DIR, "garmin_tokens")
OAUTH_STATE_FILE = os.path.join(DATA_DIR, "oauth_state.json")

ACCESS_TOKEN_TTL = 30 * 24 * 3600  # 30 días
_garmin_client = None


# ------------------------------------------------------- proveedor OAuth 2.1

class GarminAuthProvider(OAuthAuthorizationServerProvider):
    """Authorization server de un solo usuario respaldado por login de Garmin."""

    def __init__(self):
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}
        self.pending_txns: dict[str, dict] = {}
        self._load()

    # persistencia simple para sobrevivir reinicios del contenedor
    def _save(self):
        try:
            with open(OAUTH_STATE_FILE, "w") as f:
                json.dump(
                    {
                        "clients": {k: v.model_dump(mode="json") for k, v in self.clients.items()},
                        "access_tokens": {k: v.model_dump(mode="json") for k, v in self.access_tokens.items()},
                        "refresh_tokens": {k: v.model_dump(mode="json") for k, v in self.refresh_tokens.items()},
                    },
                    f,
                )
        except Exception:
            pass

    def _load(self):
        try:
            with open(OAUTH_STATE_FILE) as f:
                data = json.load(f)
            self.clients = {k: OAuthClientInformationFull(**v) for k, v in data.get("clients", {}).items()}
            self.access_tokens = {k: AccessToken(**v) for k, v in data.get("access_tokens", {}).items()}
            self.refresh_tokens = {k: RefreshToken(**v) for k, v in data.get("refresh_tokens", {}).items()}
        except Exception:
            pass

    # --- registro dinámico de clientes (claude.ai se registra solo)
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.clients[client_info.client_id] = client_info
        self._save()

    # --- paso 1: Claude pide autorización → lo mandamos a /login
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        txn = secrets.token_urlsafe(16)
        self.pending_txns[txn] = {
            "client_id": client.client_id,
            "params": params,
            "created": time.time(),
        }
        return f"{PUBLIC_URL}/login?txn={txn}"

    # llamado desde la ruta /login cuando el login de Garmin fue exitoso
    def complete_authorization(self, txn: str) -> str:
        info = self.pending_txns.pop(txn, None)
        if not info or time.time() - info["created"] > 600:
            raise ValueError("Sesión de autorización expirada; vuelve a intentar desde Claude.")
        params: AuthorizationParams = info["params"]
        code = f"gc_{secrets.token_urlsafe(32)}"
        self.auth_codes[code] = AuthorizationCode(
            code=code,
            scopes=params.scopes or ["garmin:read"],
            expires_at=time.time() + 300,
            client_id=info["client_id"],
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
        )
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    # --- paso 2: intercambio de código por tokens
    async def load_authorization_code(self, client, authorization_code: str):
        code = self.auth_codes.get(authorization_code)
        if code and code.expires_at and code.expires_at < time.time():
            self.auth_codes.pop(authorization_code, None)
            return None
        return code

    async def exchange_authorization_code(self, client, authorization_code: AuthorizationCode) -> OAuthToken:
        self.auth_codes.pop(authorization_code.code, None)
        access = f"gat_{secrets.token_urlsafe(32)}"
        refresh = f"grt_{secrets.token_urlsafe(32)}"
        now = time.time()
        self.access_tokens[access] = AccessToken(
            token=access, client_id=client.client_id,
            scopes=authorization_code.scopes, expires_at=int(now + ACCESS_TOKEN_TTL),
        )
        self.refresh_tokens[refresh] = RefreshToken(
            token=refresh, client_id=client.client_id, scopes=authorization_code.scopes,
        )
        self._save()
        return OAuthToken(
            access_token=access, token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL, refresh_token=refresh,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_refresh_token(self, client, refresh_token: str):
        return self.refresh_tokens.get(refresh_token)

    async def exchange_refresh_token(self, client, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        self.refresh_tokens.pop(refresh_token.token, None)
        access = f"gat_{secrets.token_urlsafe(32)}"
        refresh = f"grt_{secrets.token_urlsafe(32)}"
        now = time.time()
        use_scopes = scopes or refresh_token.scopes
        self.access_tokens[access] = AccessToken(
            token=access, client_id=client.client_id,
            scopes=use_scopes, expires_at=int(now + ACCESS_TOKEN_TTL),
        )
        self.refresh_tokens[refresh] = RefreshToken(
            token=refresh, client_id=client.client_id, scopes=use_scopes,
        )
        self._save()
        return OAuthToken(
            access_token=access, token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL, refresh_token=refresh,
            scope=" ".join(use_scopes),
        )

    # --- validación en cada request de herramienta
    async def load_access_token(self, token: str) -> AccessToken | None:
        at = self.access_tokens.get(token)
        if at and at.expires_at and at.expires_at < time.time():
            self.access_tokens.pop(token, None)
            self._save()
            return None
        return at

    async def revoke_token(self, token) -> None:
        self.access_tokens.pop(getattr(token, "token", None), None)
        self.refresh_tokens.pop(getattr(token, "token", None), None)
        self._save()


provider = GarminAuthProvider()

mcp = MCPServer(
    name="garmin_mcp",
    instructions=(
        "Conector de solo lectura para Garmin Connect (incluye plan de "
        "TrainingPeaks vía calendario Garmin). Fechas YYYY-MM-DD."
    ),
    auth_server_provider=provider,
    auth=AuthSettings(
        issuer_url=AnyUrl(PUBLIC_URL),
        resource_server_url=AnyUrl(f"{PUBLIC_URL}/mcp"),
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=["garmin:read"], default_scopes=["garmin:read"],
        ),
        required_scopes=["garmin:read"],
    ),
)


# --------------------------------------------------- pantalla de autorización

_LOGIN_PAGE = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Autorizar Garmin Connect</title><style>
body{{font-family:-apple-system,system-ui,sans-serif;background:#0f1116;color:#eee;
display:flex;justify-content:center;padding:40px 16px}}
.card{{background:#1a1d24;border:1px solid #2a2e38;border-radius:14px;padding:28px;
max-width:400px;width:100%}}h1{{font-size:1.2rem;margin:0 0 6px}}p{{color:#9aa;font-size:.88rem}}
label{{display:block;margin:14px 0 4px;font-size:.85rem;color:#bcc}}
input{{width:100%;padding:11px;border-radius:8px;border:1px solid #333a46;
background:#11141a;color:#eee;font-size:1rem;box-sizing:border-box}}
button{{width:100%;margin-top:20px;padding:12px;border:0;border-radius:8px;
background:#0a84ff;color:#fff;font-size:1rem;font-weight:600}}
.err{{background:#3a1416;border:1px solid #6e2226;color:#f2b8bb;padding:10px;
border-radius:8px;font-size:.85rem;margin-top:12px}}
.note{{font-size:.75rem;color:#778;margin-top:16px}}</style></head><body>
<div class="card"><h1>Conectar Garmin Connect</h1>
<p>Claude solicita acceso de <b>solo lectura</b> a tus datos de Garmin.
Inicia sesión para autorizar.</p>
<form method="post" action="/login">
<input type="hidden" name="txn" value="{txn}">
<label>Email de Garmin</label><input name="email" type="email" required autocomplete="username">
<label>Contraseña</label><input name="password" type="password" required autocomplete="current-password">
<label>Código MFA (solo si tienes verificación en dos pasos)</label>
<input name="mfa" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="opcional">
{error}
<button type="submit">Autorizar acceso</button></form>
<p class="note">Tus credenciales se usan una sola vez para iniciar sesión con
Garmin en este servidor (que tú controlas) y no se almacenan; solo se guardan
los tokens de sesión de Garmin. Claude nunca ve tu contraseña.</p>
</div></body></html>"""


@mcp.custom_route("/login", methods=["GET"])
async def login_page(request: Request):
    txn = request.query_params.get("txn", "")
    if txn not in provider.pending_txns:
        return HTMLResponse("<p style='font-family:sans-serif'>Sesión inválida o expirada. Vuelve a agregar/conectar el conector desde Claude.</p>", status_code=400)
    return HTMLResponse(_LOGIN_PAGE.format(txn=html.escape(txn), error=""))


@mcp.custom_route("/login", methods=["POST"])
async def login_submit(request: Request):
    form = await request.form()
    txn = str(form.get("txn", ""))
    email = str(form.get("email", "")).strip()
    password = str(form.get("password", ""))
    mfa = str(form.get("mfa", "")).strip()

    if txn not in provider.pending_txns:
        return HTMLResponse("<p style='font-family:sans-serif'>Sesión expirada. Reintenta desde Claude.</p>", status_code=400)

    global _garmin_client
    try:
        from garminconnect import Garmin
        kwargs = {"email": email, "password": password}
        if mfa:
            kwargs["prompt_mfa"] = lambda: mfa
        client = Garmin(**kwargs)
        client.login()
        garth_client = getattr(client, "garth", None) or getattr(client, "client", None)
        if garth_client is not None:
            try:
                garth_client.dump(GARMIN_TOKEN_DIR)
            except Exception:
                pass  # sin persistencia; la sesión vive en memoria
        _garmin_client = client
    except Exception as e:
        err = f'<div class="err">No se pudo iniciar sesión: {html.escape(str(e))}<br>Si tienes MFA, incluye el código.</div>'
        return HTMLResponse(_LOGIN_PAGE.format(txn=html.escape(txn), error=err), status_code=401)

    try:
        redirect_to = provider.complete_authorization(txn)
    except ValueError as e:
        return HTMLResponse(f"<p style='font-family:sans-serif'>{html.escape(str(e))}</p>", status_code=400)
    return RedirectResponse(redirect_to, status_code=302)


# ------------------------------------------------------------- cliente Garmin

def _get_client():
    global _garmin_client
    if _garmin_client is not None:
        return _garmin_client
    from garminconnect import Garmin
    client = Garmin()
    client.login(GARMIN_TOKEN_DIR)  # tokens guardados en la autorización
    _garmin_client = client
    return _garmin_client


def _ok(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


def _err(e: Exception, hint: str = "") -> str:
    msg = {"error": f"{type(e).__name__}: {e}"}
    if hint:
        msg["hint"] = hint
    return json.dumps(msg, ensure_ascii=False)


def _today() -> str:
    return date.today().isoformat()


# ---------------------------------------------------------------- herramientas

@mcp.tool(name="garmin_list_activities", annotations={"title": "Listar actividades", "readOnlyHint": True})
def garmin_list_activities(limit: int = 10, start: int = 0) -> str:
    """Lista las actividades más recientes (carreras, fuerza, etc.).

    Args:
        limit: número de actividades (1-50, default 10).
        start: offset para paginación.
    """
    try:
        acts = _get_client().get_activities(start, min(max(limit, 1), 50))
        slim = [
            {
                "activityId": a.get("activityId"),
                "name": a.get("activityName"),
                "type": (a.get("activityType") or {}).get("typeKey"),
                "startLocal": a.get("startTimeLocal"),
                "distance_m": a.get("distance"),
                "duration_s": a.get("duration"),
                "avgHR": a.get("averageHR"),
                "maxHR": a.get("maxHR"),
                "avgSpeed_mps": a.get("averageSpeed"),
                "calories": a.get("calories"),
                "trainingEffect_aerobic": a.get("aerobicTrainingEffect"),
                "trainingEffect_anaerobic": a.get("anaerobicTrainingEffect"),
            }
            for a in acts
        ]
        return _ok(slim)
    except Exception as e:
        return _err(e, "Si es error de sesión, reconecta el conector para autorizar de nuevo.")


@mcp.tool(name="garmin_get_activity", annotations={"title": "Detalle de actividad", "readOnlyHint": True})
def garmin_get_activity(activity_id: int, include_splits: bool = True) -> str:
    """Detalle completo de una actividad por ID, con splits opcionales."""
    try:
        c = _get_client()
        out = {"summary": c.get_activity(activity_id)}
        if include_splits:
            try:
                out["splits"] = c.get_activity_splits(activity_id)
            except Exception as e:
                out["splits_error"] = str(e)
        return _ok(out)
    except Exception as e:
        return _err(e)


@mcp.tool(name="garmin_get_scheduled_workouts", annotations={"title": "Workouts planeados (incl. TrainingPeaks)", "readOnlyHint": True})
def garmin_get_scheduled_workouts(start_day: str = "", end_day: str = "") -> str:
    """Workouts planeados en el calendario Garmin — incluye los que
    TrainingPeaks sincroniza automáticamente (conexión TP → Garmin).

    Args:
        start_day: inicio YYYY-MM-DD (default: hoy).
        end_day: fin YYYY-MM-DD (default: hoy + 7 días).
    """
    try:
        start = start_day or _today()
        end = end_day or (date.fromisoformat(start) + timedelta(days=7)).isoformat()
        return _ok(_get_client().get_scheduled_workouts(start, end))
    except Exception as e:
        return _err(e, "Verifica que TrainingPeaks → Garmin esté conectado en TP.")


@mcp.tool(name="garmin_get_workout_detail", annotations={"title": "Detalle de workout planeado", "readOnlyHint": True})
def garmin_get_workout_detail(workout_id: int) -> str:
    """Estructura completa de un workout planeado (pasos, intervalos, targets)."""
    try:
        return _ok(_get_client().get_workout_by_id(workout_id))
    except Exception as e:
        return _err(e)


@mcp.tool(name="garmin_get_sleep", annotations={"title": "Datos de sueño", "readOnlyHint": True})
def garmin_get_sleep(day: str = "") -> str:
    """Sueño de una noche: duración, fases, sleep score, HRV, FC en reposo."""
    try:
        data = _get_client().get_sleep_data(day or _today())
        daily = data.get("dailySleepDTO", {}) if isinstance(data, dict) else {}
        slim = {
            "date": daily.get("calendarDate"),
            "sleepTime_s": daily.get("sleepTimeSeconds"),
            "deep_s": daily.get("deepSleepSeconds"),
            "light_s": daily.get("lightSleepSeconds"),
            "rem_s": daily.get("remSleepSeconds"),
            "awake_s": daily.get("awakeSleepSeconds"),
            "sleepScore": (daily.get("sleepScores") or {}).get("overall", {}).get("value")
            if isinstance(daily.get("sleepScores"), dict) else None,
            "avgOvernightHrv": data.get("avgOvernightHrv"),
            "restingHeartRate": data.get("restingHeartRate"),
        }
        return _ok(slim)
    except Exception as e:
        return _err(e)


@mcp.tool(name="garmin_get_hrv", annotations={"title": "HRV nocturno", "readOnlyHint": True})
def garmin_get_hrv(day: str = "") -> str:
    """HRV nocturno: última noche, promedio 7 días, baseline y estatus."""
    try:
        data = _get_client().get_hrv_data(day or _today())
        summary = data.get("hrvSummary", data) if isinstance(data, dict) else data
        return _ok(summary)
    except Exception as e:
        return _err(e)


@mcp.tool(name="garmin_get_body_battery", annotations={"title": "Body Battery", "readOnlyHint": True})
def garmin_get_body_battery(day: str = "") -> str:
    """Body Battery del día."""
    try:
        d = day or _today()
        return _ok(_get_client().get_body_battery(d, d))
    except Exception as e:
        return _err(e)


@mcp.tool(name="garmin_get_training_readiness", annotations={"title": "Training Readiness", "readOnlyHint": True})
def garmin_get_training_readiness(day: str = "") -> str:
    """Training Readiness score y factores."""
    try:
        return _ok(_get_client().get_training_readiness(day or _today()))
    except Exception as e:
        return _err(e, "Requiere reloj compatible con Training Readiness.")


@mcp.tool(name="garmin_get_training_status", annotations={"title": "Training Status", "readOnlyHint": True})
def garmin_get_training_status(day: str = "") -> str:
    """Estatus de entrenamiento, carga aguda/crónica y VO2max."""
    try:
        return _ok(_get_client().get_training_status(day or _today()))
    except Exception as e:
        return _err(e)


@mcp.tool(name="garmin_get_daily_stats", annotations={"title": "Resumen diario", "readOnlyHint": True})
def garmin_get_daily_stats(day: str = "") -> str:
    """Pasos, calorías, FC reposo, estrés y minutos de intensidad del día."""
    try:
        data = _get_client().get_stats(day or _today())
        keys = [
            "calendarDate", "totalSteps", "totalKilocalories",
            "activeKilocalories", "restingHeartRate", "minHeartRate",
            "maxHeartRate", "averageStressLevel", "maxStressLevel",
            "stressDuration", "moderateIntensityMinutes",
            "vigorousIntensityMinutes", "bodyBatteryHighestValue",
            "bodyBatteryLowestValue", "floorsAscended",
        ]
        slim = {k: data.get(k) for k in keys if isinstance(data, dict)}
        return _ok(slim or data)
    except Exception as e:
        return _err(e)


@mcp.tool(name="garmin_get_week_summary", annotations={"title": "Resumen semanal", "readOnlyHint": True})
def garmin_get_week_summary(end_day: str = "") -> str:
    """Últimos 7 días: sueño, estrés, Body Battery y FC reposo por día."""
    try:
        c = _get_client()
        end = date.fromisoformat(end_day) if end_day else date.today()
        out = []
        for i in range(6, -1, -1):
            d = (end - timedelta(days=i)).isoformat()
            row = {"date": d}
            try:
                s = c.get_stats(d) or {}
                row.update({
                    "steps": s.get("totalSteps"),
                    "restingHR": s.get("restingHeartRate"),
                    "avgStress": s.get("averageStressLevel"),
                    "bodyBattery_max": s.get("bodyBatteryHighestValue"),
                    "bodyBattery_min": s.get("bodyBatteryLowestValue"),
                })
            except Exception:
                pass
            try:
                sl = c.get_sleep_data(d) or {}
                daily = sl.get("dailySleepDTO", {})
                row["sleep_h"] = round((daily.get("sleepTimeSeconds") or 0) / 3600, 2)
            except Exception:
                pass
            out.append(row)
        return _ok(out)
    except Exception as e:
        return _err(e)


# ----------------------------------------------------------------------- main

def main():
    port = int(os.environ.get("PORT", "8000"))
    app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    print(f"[garmin_mcp] OAuth listo. Conector: {PUBLIC_URL}/mcp")
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
