# garmin_mcp — Conector Garmin con autorización (experiencia tipo Strava)

Agregas el conector en claude.ai → Claude abre una pantalla de autorización →
inicias sesión con Garmin **una sola vez** → autorizas → conectado. Sin
contraseñas en variables ni secrets en la URL. Incluye tu plan de
**TrainingPeaks** (leído del calendario Garmin vía la conexión TP → Garmin).

## Cómo funciona la autorización
El servidor implementa OAuth 2.1 (registro dinámico + PKCE), que es lo que
claude.ai usa con conectores como Strava. Al conectar:
1. Claude te redirige a la pantalla `/login` de TU servidor
2. Pones tu email/contraseña de Garmin (+ código MFA si lo tienes activado)
3. El servidor inicia sesión con Garmin, guarda solo los tokens de sesión
   (tu contraseña no se almacena) y te regresa a Claude ya autorizado
4. Claude recibe un access token propio del conector (válido 30 días, con
   refresh automático) — nunca ve tus credenciales de Garmin

## Despliegue en Railway (~10 min)
1. Repo en GitHub con: `server_oauth.py`, `requirements.txt`, `Dockerfile`
2. [railway.app](https://railway.app) → New Project → Deploy from GitHub repo
3. Settings → Networking → **Generate Domain** (ej. `xxxx.up.railway.app`)
4. Variables → agrega solo una:
   - `PUBLIC_URL` = `https://xxxx.up.railway.app` (tu dominio del paso 3)
5. (Opcional, recomendado) agrega un **Volume** montado en `/data` para que
   la sesión sobreviva reinicios del contenedor
6. Redeploy

## Conectar en claude.ai
1. Configuración → Conectores → **Agregar conector personalizado**
2. URL: `https://xxxx.up.railway.app/mcp`
3. Claude detecta el OAuth solo → botón **Conectar** → pantalla de login → autoriza
4. Aparece "garmin_mcp" con 11 herramientas de solo lectura

## Herramientas
| Herramienta | Qué devuelve |
|---|---|
| `garmin_get_scheduled_workouts` | **Plan de TrainingPeaks** + workouts planeados |
| `garmin_get_workout_detail` | Estructura del workout (intervalos, targets) |
| `garmin_list_activities` / `garmin_get_activity` | Actividades y splits |
| `garmin_get_sleep` / `garmin_get_hrv` | Sueño, fases, sleep score, HRV |
| `garmin_get_body_battery` / `garmin_get_training_readiness` | Recuperación |
| `garmin_get_training_status` | Carga, VO2max |
| `garmin_get_daily_stats` / `garmin_get_heart_rates`-equiv | Estrés, pasos, FC |
| `garmin_get_week_summary` | 7 días: sueño, estrés, Body Battery |

## Seguridad
- Solo lectura; nada se modifica en tu cuenta Garmin.
- Tu contraseña se usa una vez en TU servidor y no se guarda; solo tokens de sesión.
- Es un servidor de un solo usuario: no compartas la URL públicamente — quien
  la conecte y complete el login con SUS credenciales no verá tus datos, pero
  para desconectar/revocar: elimina el conector en Claude y borra el volumen `/data`.
- Garmin no ofrece API oficial para individuos; esto usa la librería
  comunitaria `garminconnect`. No es un producto oficial de Garmin.

## Probado
Flujo completo verificado: discovery OAuth → registro dinámico de cliente →
authorize con PKCE → pantalla de login → emisión de código → intercambio por
token → llamada MCP autenticada → rechazo 401 sin token.
