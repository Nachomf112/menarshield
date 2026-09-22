#!/usr/bin/env python3
"""
MenarShield — escáner de seguridad ligero para configuraciones de Claude Code / MCP.
Herramienta propia de Menarguez-IA Solutions.

Sin dependencias externas obligatorias ni llamadas a LLM. Cubre 6 categorías:
  1. Secretos hardcodeados (tokens de Telegram, Supabase, GitHub, AWS, Anthropic/OpenAI,
     Stripe, JWT, claves privadas PEM, y patrón genérico VAR=valor-de-alta-entropía).
     Los almacenes de credenciales esperados (.aws/credentials, .ssh/id_rsa,
     .claude/.credentials.json, etc.) no se escanean por contenido, solo por permisos.
  2. Permisos peligrosos en settings.json / mcp.json de Claude Code (allow-lists
     demasiado amplias, deny vacío).
  3. Permisos de fichero inseguros en hooks/ (escribible por grupo/otros).
  4. Docker Compose / Dockerfile inseguros (privileged, docker.sock montado,
     network_mode: host, puertos en 0.0.0.0, imágenes sin versión fijada,
     contenedor corriendo como root). Se parsea el YAML de verdad si `pyyaml`
     está instalado; si no, cae a un análisis por regex.
  5. Flags de debug activos en producción (Flask/Django/ASP.NET Core).
  6. .env sin cubrir por .gitignore en repos con git.

Uso:
    python3 menarshield.py                          # menú interactivo (elige ruta y formato)
    python3 menarshield.py [ruta]                    # escanea y muestra menú de exportación
    python3 menarshield.py [ruta] --formato html      # exporta directo, sin menú (para scripts/n8n)
    python3 menarshield.py [ruta] --formato md
    python3 menarshield.py [ruta] --formato pdf       # genera también el .html de regalo
    python3 menarshield.py [ruta] --formato json      # también deja el .json en disco (sirve de base para --diff)
    python3 menarshield.py [ruta] --formato sarif     # para GitHub code scanning / CI
    python3 menarshield.py [ruta] --formato todos     # md + html + pdf + json de una vez
    python3 menarshield.py [ruta] --fail-on=warn       # exit code 1 también con warnings
    python3 menarshield.py [ruta] --out mi-informe     # nombre base de los ficheros generados
    python3 menarshield.py [ruta] --diff               # solo hallazgos nuevos vs. el último JSON en esa carpeta
    python3 menarshield.py [ruta] --diff otro.json      # diff contra un JSON concreto
    python3 menarshield.py [ruta] --sin-ignorar         # ignora el fichero .menarshieldignore
    python3 menarshield.py --version

Ficheros de configuración:
    .menarshieldignore   Igual que un .gitignore: un patrón glob por línea
                          (opcionalmente "patrón:línea" para una línea exacta),
                          "#" para comentarios. Se aplica siempre salvo --sin-ignorar.

Códigos de salida:
    0 = limpio
    1 = solo warnings (si --fail-on=warn)
    2 = al menos un hallazgo CRÍTICO (o warnings si --fail-on=warn no se usa y hay críticos)

Dependencias: ninguna para escanear / texto / Markdown / HTML / JSON / SARIF (solo
librería estándar). `pyyaml` es opcional y mejora el análisis de Docker Compose.
Para exportar a PDF se usa, si está instalada, `weasyprint` o `xhtml2pdf`; si ninguna
está disponible, se genera el HTML igualmente y se explica cómo pasarlo a PDF
(Ctrl/Cmd+P → "Guardar como PDF" desde el navegador).
"""

import argparse
import base64
import datetime
import fnmatch
import json
import mimetypes
import os
import re
import stat
import sys
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml  # type: ignore
    YAML_DISPONIBLE = True
except ImportError:
    YAML_DISPONIBLE = False

# ─── Identidad / marca ──────────────────────────────────────────────────────────
MARCA = "Menarguez-IA Solutions"
PRODUCTO = "MenarShield"
URL_MARCA = "https://ai.menarguez-ia.com/"
LOGO_PATH_DEFAULT = Path(__file__).parent / "logo-menarguez-ia.png"
VERSION = "1.4.2"
VERSION_FECHA = "2026-09-22"

BANNER_ASCII = r"""
 __  __                       ____  _     _      _     _
|  \/  | ___ _ __   __ _ _ __/ ___|| |__ (_) ___| | __| |
| |\/| |/ _ \ '_ \ / _` | '__\___ \| '_ \| |/ _ \ |/ _` |
| |  | |  __/ | | | (_| | |   ___) | | | | |  __/ | (_| |
|_|  |_|\___|_| |_|\__,_|_|  |____/|_| |_|_|\___|_|\__,_|
"""

# ─── Directorios/ficheros a ignorar siempre ────────────────────────────────────
IGNORE_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    ".next", ".turbo", "target", ".cache", "vendor",
    # Código de librerías instaladas, no tuyo — escanearlo solo genera ruido
    # (regexes de entropía detectando tablas de colores, JS minificado, etc.)
    "site-packages", "dist-packages", ".npm", ".nvm",
}

# Almacenes de credenciales locales conocidos y esperados: su función es
# guardar el secreto real ahí (protegido por permisos de fichero, no por
# ausencia de contenido), así que marcarlos como "secreto hardcodeado
# filtrado" es una falsa alarma — no son código fuente ni algo que vaya a
# subirse a un repo. Se comparan por el final de la ruta relativa.
ALMACENES_CREDENCIALES_ESPERADOS = (
    ".claude/.credentials.json",
    ".aws/credentials",
    ".netrc",
    ".npmrc",
    ".docker/config.json",
    ".kube/config",
    ".config/gh/hosts.yml",
    ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa",
)

# Ficheros de credenciales PÚBLICAS y conocidas: el mismo fichero, con el
# mismo bloque PEM, lo descarga cualquiera desde el servicio — no son un
# secreto de nadie. Se comparan solo por el NOMBRE de fichero (fnmatch,
# sin distinguir mayúsculas), nunca por extensión completa: un .ovpn con
# una clave privada real de tu propio Tailscale/OpenVPN/Wazuh debe seguir
# detectándose con normalidad, solo se descartan estos nombres exactos.
PATRONES_CREDENCIALES_PUBLICAS = (
    "vpnbook-*.ovpn",  # certificados de demostración del servicio gratuito VPNBook
)

# Extensiones binarias/no relevantes que no merece la pena escanear como texto
# (una carpeta de Descargas típica está llena de estas — sin excluirlas, cada
# una se lee entera como "texto" hasta MAX_FILE_SIZE y se pasa por todos los
# regexes de secretos, lo que puede convertir un escaneo de minutos en horas)
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff", ".psd",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp4", ".mp3", ".mov", ".mkv", ".avi", ".wav", ".flac", ".ogg", ".m4a", ".m4v", ".webm",
    ".wasm", ".exe", ".msi", ".dmg", ".iso", ".apk", ".deb", ".rpm",
    ".dll", ".so", ".dylib", ".bin", ".class", ".jar", ".whl",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp",
    ".lock",  # package-lock.json etc. generan demasiado ruido de hashes
}

MAX_FILE_SIZE = 2 * 1024 * 1024  # no escanear ficheros de más de 2MB como texto

# ─── Patrones de secretos ───────────────────────────────────────────────────────
SECRET_PATTERNS = [
    ("Token de bot de Telegram",
     re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"), "CRITICO"),
    ("Clave de servicio Supabase (JWT)",
     re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "CRITICO"),
    ("AWS Access Key ID",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "CRITICO"),
    ("GitHub Personal Access Token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "CRITICO"),
    ("Clave de API de Anthropic",
     re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "CRITICO"),
    ("Clave de API de OpenAI",
     re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "CRITICO"),
    ("Clave de Stripe (live)",
     re.compile(r"\b(sk|pk)_live_[A-Za-z0-9]{20,}\b"), "CRITICO"),
    ("Bloque de clave privada PEM",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"), "CRITICO"),
    ("Asignación de credencial de alta entropía",
     re.compile(
         # incluye "key" a secas (SUPABASE_KEY, DASHBOARD_KEY...) además de
         # api_key/secret/token/password — a costa de algún falso positivo
         # ocasional, preferible a dejar pasar una clave real
         r"(?i)(api[_-]?key|[a-z_]*key|secret|token|password|passwd|pwd)['\"]?\s*[:=]\s*"
         r"['\"]?([A-Za-z0-9_\-/+]{20,})['\"]?"
     ), "ADVERTENCIA"),
]

PLACEHOLDER_RE = re.compile(
    r"(?i)(changeme|^your[_-]|_here$|xxx+|placeholder|"
    r"^<[^>]+>$|^\$\{[^}]+\}$|process\.env|os\.environ|example|dummy|^test[_-])"
)

# Técnica MITRE ATT&CK asociada a cada categoría de hallazgo (cuando hay una
# correspondencia real y directa; se deja vacío antes que forzar una mala
# atribución).
CATEGORIA_MITRE = {
    "secreto": "T1552.001 — Unsecured Credentials: Credentials In Files",
    "permisos": "T1548 — Abuse Elevation Control Mechanism",
    "mcp-config": "T1552 — Unsecured Credentials",
    "permisos-fichero": "T1222.002 — File and Directory Permissions Modification (Linux/Mac)",
    "docker": "T1611 — Escape to Host",
    "env-git": "T1552.001 — Unsecured Credentials: Credentials In Files",
}


@dataclass
class Finding:
    categoria: str
    severidad: str
    ruta: str
    detalle: str
    linea: int = 0
    mitre: str = ""

    def __post_init__(self):
        if not self.mitre:
            self.mitre = CATEGORIA_MITRE.get(self.categoria, "")


@dataclass
class Reporte:
    hallazgos: list = field(default_factory=list)

    def add(self, f: Finding):
        self.hallazgos.append(f)

    @property
    def criticos(self):
        return [f for f in self.hallazgos if f.severidad == "CRITICO"]

    @property
    def advertencias(self):
        return [f for f in self.hallazgos if f.severidad == "ADVERTENCIA"]

    @property
    def por_categoria(self):
        cats = {}
        for f in self.hallazgos:
            cats.setdefault(f.categoria, []).append(f)
        return cats

    def consolidar(self):
        """Elimina duplicados EXACTOS (misma categoría+severidad+ruta+línea+
        detalle) — el caso típico es una misma línea con dos coincidencias
        del mismo patrón (dos claves distintas casando el mismo texto de
        detalle). No fusiona hallazgos que solo comparten fichero: dos
        problemas distintos en el mismo docker-compose.yml (p. ej.
        'privileged' y el socket de Docker montado) siguen siendo dos filas,
        no una sola con el texto pegado."""
        vistos = set()
        nuevos = []
        for f in self.hallazgos:
            clave = (f.categoria, f.severidad, f.ruta, f.linea, f.detalle)
            if clave in vistos:
                continue
            vistos.add(clave)
            nuevos.append(f)
        self.hallazgos = nuevos

    def fingerprint(self, f: Finding) -> tuple:
        return (f.categoria, f.severidad, f.ruta, f.linea, f.detalle)


# ─── Escaneo ─────────────────────────────────────────────────────────────────────

def iter_text_files(root: Path, progreso: bool = False):
    """Recorre el árbol UNA sola vez y va cediendo los ficheros de texto
    elegibles. Si progreso=True, imprime un contador en vivo (misma línea)
    para dejar claro que el escaneo sigue avivo en carpetas muy grandes."""
    vistos = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".git")]
        for name in filenames:
            p = Path(dirpath) / name
            if progreso:
                vistos += 1
                if vistos % 250 == 0:
                    print(f"\r  ... {vistos} ficheros revisados", end="", flush=True)
            if p.suffix.lower() in SKIP_EXT:
                continue
            try:
                if p.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            yield p
    if progreso and vistos >= 250:
        print(f"\r  ... {vistos} ficheros revisados en total{' ' * 10}")


def _es_almacen_credenciales_esperado(rel: str) -> bool:
    rel_posix = rel.replace(os.sep, "/")
    return any(rel_posix == s or rel_posix.endswith("/" + s) for s in ALMACENES_CREDENCIALES_ESPERADOS)


def _es_credencial_publica_conocida(nombre: str) -> bool:
    nombre_lower = nombre.lower()
    return any(fnmatch.fnmatch(nombre_lower, patron) for patron in PATRONES_CREDENCIALES_PUBLICAS)


def scan_secrets(root: Path, reporte: Reporte, archivos):
    for path in archivos:
        rel = str(path.relative_to(root))
        if _es_credencial_publica_conocida(path.name):
            # Certificado público y conocido (ej. demo de VPNBook) — el mismo
            # fichero, con el mismo contenido, lo tiene cualquiera. No es una
            # fuga de nadie: se descarta sin generar ni siquiera un aviso.
            continue
        if _es_almacen_credenciales_esperado(rel):
            try:
                mode = path.stat().st_mode
            except OSError:
                mode = 0
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                reporte.add(Finding(
                    categoria="secreto",
                    severidad="ADVERTENCIA",
                    ruta=rel,
                    detalle="Almacén de credenciales local (contenido esperado, no es una fuga) "
                            "pero con permisos abiertos a grupo/otros — debería ser legible solo "
                            "por el propietario (chmod 600)",
                ))
            # Se salta el escaneo de contenido: aquí SÍ se espera un secreto real.
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for nombre, patron, severidad in SECRET_PATTERNS:
                for m in patron.finditer(line):
                    valor = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
                    if PLACEHOLDER_RE.search(valor.strip("'\"")):
                        continue
                    reporte.add(Finding(
                        categoria="secreto",
                        severidad=severidad,
                        ruta=rel,
                        detalle=f"{nombre} (patrón detectado en la línea)",
                        linea=lineno,
                    ))


CLAUDE_CONFIG_NAMES = {"settings.json", "mcp.json", ".mcp.json"}


def scan_permissions(root: Path, reporte: Reporte):
    for path in iter_text_files(root):
        if path.name not in CLAUDE_CONFIG_NAMES:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            continue

        perms = data.get("permissions") if isinstance(data, dict) else None
        if not isinstance(perms, dict):
            continue

        allow = perms.get("allow", [])
        deny = perms.get("deny", [])
        rel = str(path.relative_to(root))

        if isinstance(allow, list):
            for regla in allow:
                regla_str = str(regla)
                es_bash_amplio = regla_str.strip() == "*" or regla_str.startswith("Bash(") and any(
                    p in regla_str for p in ("Bash(*)", "Bash(rm *)", "Bash(sudo *)")
                )
                if es_bash_amplio:
                    reporte.add(Finding(
                        categoria="permisos",
                        severidad="CRITICO",
                        ruta=rel,
                        detalle=f'Regla de permiso demasiado amplia (ejecución de comandos) en "allow": {regla!r}',
                    ))
                elif "(*)" in regla_str and not regla_str.startswith("Bash("):
                    reporte.add(Finding(
                        categoria="permisos",
                        severidad="ADVERTENCIA",
                        ruta=rel,
                        detalle=f'Regla de permiso con wildcard en "allow": {regla!r} (revisa si el alcance es intencional)',
                    ))

        if isinstance(deny, list) and len(deny) == 0 and isinstance(allow, list) and len(allow) > 0:
            reporte.add(Finding(
                categoria="permisos",
                severidad="ADVERTENCIA",
                ruta=rel,
                detalle='"deny" está vacío mientras "allow" tiene reglas — sin lista negra de respaldo',
            ))

        mcp_servers = data.get("mcpServers") if isinstance(data, dict) else None
        if isinstance(mcp_servers, dict):
            for nombre_srv, cfg in mcp_servers.items():
                if not isinstance(cfg, dict):
                    continue
                env = cfg.get("env", {})
                if isinstance(env, dict):
                    for k, v in env.items():
                        if isinstance(v, str) and not PLACEHOLDER_RE.search(v.strip("'\"")) and len(v) > 20:
                            reporte.add(Finding(
                                categoria="mcp-config",
                                severidad="ADVERTENCIA",
                                ruta=rel,
                                detalle=f'Servidor MCP "{nombre_srv}": variable de entorno "{k}" '
                                        f'parece contener un valor hardcodeado en vez de una referencia',
                            ))


def scan_hooks(root: Path, reporte: Reporte):
    hook_dirs = []
    for dirpath, dirnames, _ in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for d in dirnames:
            if d == "hooks":
                hook_dirs.append(Path(dirpath) / d)

    for hdir in hook_dirs:
        for path in hdir.rglob("*"):
            if not path.is_file():
                continue
            try:
                mode = path.stat().st_mode
            except OSError:
                continue
            rel = str(path.relative_to(root))

            if mode & stat.S_IWOTH:
                reporte.add(Finding(
                    categoria="permisos-fichero",
                    severidad="CRITICO",
                    ruta=rel,
                    detalle="Hook escribible por 'otros' (world-writable) — cualquier usuario del sistema podría modificarlo",
                ))
            elif mode & stat.S_IWGRP:
                reporte.add(Finding(
                    categoria="permisos-fichero",
                    severidad="ADVERTENCIA",
                    ruta=rel,
                    detalle="Hook escribible por el grupo — revisa si es intencional",
                ))

            if path.suffix in (".sh", "") and not (mode & stat.S_IXUSR):
                reporte.add(Finding(
                    categoria="permisos-fichero",
                    severidad="ADVERTENCIA",
                    ruta=rel,
                    detalle="Hook sin permiso de ejecución para el propietario — puede fallar silenciosamente",
                ))


DOCKER_COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}


def _revisar_servicio_compose(rel: str, nombre_servicio: str, svc: dict, reporte: Reporte):
    """Aplica las mismas comprobaciones que la versión por regex, pero sobre
    un servicio ya parseado como dict (parseo YAML real vía PyYAML —
    más fiable que el texto plano ante formatos poco habituales)."""
    if not isinstance(svc, dict):
        return

    if svc.get("privileged") is True:
        reporte.add(Finding(
            categoria="docker", severidad="CRITICO", ruta=rel,
            detalle=f"Servicio '{nombre_servicio}': 'privileged: true' — acceso equivalente a root "
                    "sobre el host, rompe el aislamiento del contenedor",
        ))

    volumenes = svc.get("volumes") or []
    for vol in volumenes:
        origen = vol.get("source", "") if isinstance(vol, dict) else str(vol)
        if "/var/run/docker.sock" in origen:
            reporte.add(Finding(
                categoria="docker", severidad="CRITICO", ruta=rel,
                detalle=f"Servicio '{nombre_servicio}': socket de Docker (/var/run/docker.sock) montado — "
                        "quien lo comprometa controla el host completo",
            ))

    if str(svc.get("network_mode", "")).lower() == "host":
        reporte.add(Finding(
            categoria="docker", severidad="ADVERTENCIA", ruta=rel,
            detalle=f"Servicio '{nombre_servicio}': 'network_mode: host' — comparte la red del host, "
                    "sin aislamiento de puertos",
        ))

    for p in svc.get("ports") or []:
        host_ip, puerto = None, None
        if isinstance(p, dict):
            host_ip, puerto = p.get("host_ip"), p.get("published")
        elif isinstance(p, str) and p.startswith("0.0.0.0:"):
            # Solo se avisa cuando el propio texto fija 0.0.0.0 explícitamente
            # (el host_ip por defecto de Compose no aparece escrito, y no es
            # este el hallazgo que queremos señalar)
            host_ip, puerto = "0.0.0.0", p.split(":")[1]
        if host_ip == "0.0.0.0" and puerto:
            reporte.add(Finding(
                categoria="docker", severidad="ADVERTENCIA", ruta=rel,
                detalle=f"Servicio '{nombre_servicio}': puerto {puerto} publicado en 0.0.0.0 "
                        "(todas las interfaces) — revisa si debería limitarse a 127.0.0.1 o Tailscale",
            ))

    imagen = svc.get("image")
    if isinstance(imagen, str) and (imagen.endswith(":latest") or ":" not in imagen.rsplit("/", 1)[-1]):
        reporte.add(Finding(
            categoria="docker", severidad="ADVERTENCIA", ruta=rel,
            detalle=f"Servicio '{nombre_servicio}': imagen '{imagen}' sin versión fijada (usa ':latest' "
                    "implícito o explícito) — no es reproducible y puede cambiar sin aviso",
        ))


def scan_docker(root: Path, reporte: Reporte, archivos):
    """Revisa docker-compose*.yml y Dockerfile en busca de configuraciones que
    amplían la superficie de ataque de un contenedor. Con PyYAML instalado,
    parsea el YAML de verdad (más fiable); si no está disponible, o el parseo
    falla, cae a un análisis por texto que cubre los mismos patrones."""
    for path in archivos:
        if path.name not in DOCKER_COMPOSE_NAMES and path.name != "Dockerfile":
            continue
        rel = str(path.relative_to(root))
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        manejado_por_yaml = False
        if path.name in DOCKER_COMPOSE_NAMES and YAML_DISPONIBLE:
            try:
                data = yaml.safe_load(text)
                servicios = data.get("services") if isinstance(data, dict) else None
                if isinstance(servicios, dict):
                    for nombre_servicio, svc in servicios.items():
                        _revisar_servicio_compose(rel, nombre_servicio, svc, reporte)
                    manejado_por_yaml = True
            except Exception:
                manejado_por_yaml = False  # YAML raro/roto: cae al análisis por texto

        if path.name in DOCKER_COMPOSE_NAMES and not manejado_por_yaml:
            if re.search(r"privileged:\s*[\"']?true[\"']?", text, re.I):
                reporte.add(Finding(
                    categoria="docker",
                    severidad="CRITICO",
                    ruta=rel,
                    detalle="Contenedor en modo 'privileged: true' — acceso equivalente a root sobre el host, "
                            "rompe el aislamiento del contenedor",
                ))
            if "/var/run/docker.sock" in text:
                reporte.add(Finding(
                    categoria="docker",
                    severidad="CRITICO",
                    ruta=rel,
                    detalle="Socket de Docker (/var/run/docker.sock) montado dentro del contenedor — "
                            "quien comprometa este servicio controla el host completo",
                ))
            if re.search(r"network_mode:\s*[\"']?host[\"']?", text, re.I):
                reporte.add(Finding(
                    categoria="docker",
                    severidad="ADVERTENCIA",
                    ruta=rel,
                    detalle="'network_mode: host' — el contenedor comparte la red del host, sin aislamiento de puertos",
                ))
            for m in re.finditer(r"[\"']?0\.0\.0\.0:(\d{2,5}):(\d{2,5})[\"']?", text):
                reporte.add(Finding(
                    categoria="docker",
                    severidad="ADVERTENCIA",
                    ruta=rel,
                    detalle=f"Puerto {m.group(1)} publicado en 0.0.0.0 (todas las interfaces) — "
                            f"revisa si debería limitarse a 127.0.0.1 o a la red de Tailscale",
                ))
            for m in re.finditer(r"image:\s*[\"']?[\w./-]+:latest[\"']?", text, re.I):
                reporte.add(Finding(
                    categoria="docker",
                    severidad="ADVERTENCIA",
                    ruta=rel,
                    detalle="Imagen fijada a la etiqueta ':latest' — no es reproducible y puede cambiar "
                            "de contenido sin aviso (fija una versión concreta)",
                ))

        if path.name == "Dockerfile":
            if "/var/run/docker.sock" in text:
                reporte.add(Finding(
                    categoria="docker",
                    severidad="CRITICO",
                    ruta=rel,
                    detalle="Referencia al socket de Docker dentro del Dockerfile — riesgo de escape a host",
                ))
            if not re.search(r"^\s*USER\s+(?!root\b)\S+", text, re.M):
                reporte.add(Finding(
                    categoria="docker",
                    severidad="ADVERTENCIA",
                    ruta=rel,
                    detalle="Sin instrucción 'USER <no-root>' — el contenedor se ejecutará como root por defecto",
                ))


DEBUG_PATTERNS = [
    ("Flask en modo debug", re.compile(r"\bapp\.run\([^)]*debug\s*=\s*True", re.I)),
    ("Variable FLASK_DEBUG activa", re.compile(r"FLASK_DEBUG\s*=\s*1\b")),
    ("Django DEBUG=True", re.compile(r"^\s*DEBUG\s*=\s*True\b", re.M)),
    ("ASP.NET Core en entorno Development", re.compile(r"ASPNETCORE_ENVIRONMENT\s*=\s*Development", re.I)),
]


def scan_debug(root: Path, reporte: Reporte, archivos):
    """Modo debug expuesto en código o configuración: en producción filtra
    trazas, rutas internas y a veces permite ejecución remota de código
    (Flask/Werkzeug debugger)."""
    for path in archivos:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for nombre, patron in DEBUG_PATTERNS:
            m = patron.search(text)
            if m:
                lineno = text.count("\n", 0, m.start()) + 1
                reporte.add(Finding(
                    categoria="debug",
                    severidad="ADVERTENCIA",
                    ruta=str(path.relative_to(root)),
                    detalle=f"{nombre} — revisa que esto no llegue nunca a producción",
                    linea=lineno,
                ))


def scan_env_git(root: Path, reporte: Reporte):
    """Si el proyecto es un repo git y tiene ficheros .env, comprueba que
    .gitignore los excluye — es la vía más común de acabar subiendo secretos
    reales a GitHub."""
    if not (root / ".git").exists():
        return

    gitignore = root / ".gitignore"
    contenido_gitignore = ""
    if gitignore.exists():
        try:
            contenido_gitignore = gitignore.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            pass

    cubierto = bool(re.search(r"(?m)^\s*(\*\.env|\.env\*?|\.env\.\*)\s*$", contenido_gitignore))
    if cubierto:
        return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".git")]
        for name in filenames:
            if name == ".env" or (name.startswith(".env.") and name not in (".env.example", ".env.sample")):
                p = Path(dirpath) / name
                reporte.add(Finding(
                    categoria="env-git",
                    severidad="CRITICO",
                    ruta=str(p.relative_to(root)),
                    detalle="Repositorio git sin regla '.env' en .gitignore — este fichero podría acabar "
                            "subido a GitHub con secretos reales dentro",
                ))


NOMBRE_IGNORE = ".menarshieldignore"


def cargar_reglas_ignoradas(root: Path):
    """Lee .menarshieldignore en la raíz escaneada (una regla por línea,
    '#' para comentarios). Cada línea es un patrón glob sobre la ruta
    relativa (p. ej. 'dashboard/*.py' o '*.log'), opcionalmente con
    ':<línea>' al final para ignorar solo esa línea concreta de ese fichero
    ('dashboard/generate.py:11')."""
    ignore_file = root / NOMBRE_IGNORE
    if not ignore_file.exists():
        return []
    reglas = []
    try:
        for linea_raw in ignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            linea = linea_raw.strip()
            if not linea or linea.startswith("#"):
                continue
            if ":" in linea and linea.rsplit(":", 1)[1].isdigit():
                patron, num = linea.rsplit(":", 1)
                reglas.append((patron.strip(), int(num)))
            else:
                reglas.append((linea, None))
    except OSError:
        pass
    return reglas


def aplicar_ignorados(reporte: Reporte, reglas):
    if not reglas:
        return 0
    conservados = []
    descartados = 0
    for f in reporte.hallazgos:
        ruta_posix = f.ruta.replace(os.sep, "/")
        ignorado = False
        for patron, num_linea in reglas:
            if fnmatch.fnmatch(ruta_posix, patron):
                if num_linea is None or num_linea == f.linea:
                    ignorado = True
                    break
        if ignorado:
            descartados += 1
        else:
            conservados.append(f)
    reporte.hallazgos = conservados
    return descartados


# ─── Salida: terminal (colores) ─────────────────────────────────────────────────

class C:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE = "\033[94m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"


def _preparar_color_terminal():
    """En la consola clásica de Windows (cmd.exe sin Windows Terminal) los
    códigos ANSI no se interpretan y se ven como texto en bruto (←[96m...).
    Intenta activar el procesamiento de secuencias VT100 de la terminal; si
    no se puede, desactiva los colores en vez de ensuciar la pantalla."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        STD_OUTPUT_HANDLE = -11
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        modo = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(modo)):
            raise OSError("GetConsoleMode falló")
        if not kernel32.SetConsoleMode(handle, modo.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING):
            raise OSError("SetConsoleMode falló")
    except Exception:
        for atributo in ("RED", "YELLOW", "GREEN", "CYAN", "MAGENTA", "BLUE", "RESET", "BOLD", "DIM"):
            setattr(C, atributo, "")


def imprimir_banner():
    print(f"{C.CYAN}{C.BOLD}{BANNER_ASCII}{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}{PRODUCTO}{C.RESET}{C.DIM} — escáner de seguridad para Claude Code / MCP{C.RESET}")
    print(f"{C.DIM}Una herramienta de {C.RESET}{C.CYAN}{MARCA}{C.RESET}{C.DIM} · {URL_MARCA}{C.RESET}\n")


def imprimir_texto(reporte: Reporte, root: Path):
    print(f"{C.BOLD}Informe de: {root}{C.RESET}\n")

    if not reporte.hallazgos:
        print(f"{C.GREEN}{C.BOLD}✔ Sin hallazgos. Todo limpio.{C.RESET}")
        return

    for f in sorted(reporte.hallazgos, key=lambda x: (x.severidad != "CRITICO", x.ruta)):
        color = C.RED if f.severidad == "CRITICO" else C.YELLOW
        icono = "✖" if f.severidad == "CRITICO" else "⚠"
        ubicacion = f.ruta + (f":{f.linea}" if f.linea else "")
        print(f"{color}{icono} [{f.severidad}]{C.RESET} {C.BOLD}{ubicacion}{C.RESET} — {f.detalle}")
        if f.mitre:
            print(f"    {C.DIM}MITRE ATT&CK: {f.mitre}{C.RESET}")

    print(
        f"\n{C.BOLD}Resumen:{C.RESET} "
        f"{C.RED}{len(reporte.criticos)} crítico(s){C.RESET}, "
        f"{C.YELLOW}{len(reporte.advertencias)} advertencia(s){C.RESET}"
    )


def imprimir_json_stdout(reporte: Reporte, root: Path):
    print(generar_json(reporte, root))


# ─── Generadores de export ──────────────────────────────────────────────────────

def generar_json(reporte: Reporte, root: Path) -> str:
    payload = {
        "producto": PRODUCTO,
        "marca": MARCA,
        "fecha": datetime.datetime.now().isoformat(timespec="seconds"),
        "raiz": str(root),
        "criticos": len(reporte.criticos),
        "advertencias": len(reporte.advertencias),
        "hallazgos": [
            {
                "categoria": f.categoria,
                "severidad": f.severidad,
                "ruta": f.ruta,
                "linea": f.linea,
                "detalle": f.detalle,
                "mitre": f.mitre,
            }
            for f in reporte.hallazgos
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


CATEGORIA_TITULOS = {
    "secreto": "Secretos hardcodeados",
    "permisos": "Permisos peligrosos (settings.json / mcp.json)",
    "mcp-config": "Configuración de servidores MCP",
    "permisos-fichero": "Permisos de fichero inseguros (hooks/)",
    "docker": "Docker / Docker Compose",
    "debug": "Modo debug expuesto",
    "env-git": ".env sin proteger en git",
}


# ─── Modo --diff: comparar contra un escaneo anterior ──────────────────────────

def cargar_fingerprints_previos(ruta_json: Path) -> set:
    """Lee un informe JSON de una ejecución anterior de MenarShield y
    devuelve el conjunto de "huellas" (categoria, severidad, ruta, línea,
    detalle) de sus hallazgos, para poder restar y quedarnos solo con lo
    nuevo en la ejecución actual."""
    try:
        data = json.loads(ruta_json.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return set()
    huellas = set()
    for h in data.get("hallazgos", []):
        huellas.add((
            h.get("categoria", ""), h.get("severidad", ""),
            h.get("ruta", ""), h.get("linea", 0), h.get("detalle", ""),
        ))
    return huellas


def aplicar_diff(reporte: Reporte, huellas_previas: set) -> int:
    """Deja en el informe solo los hallazgos que NO estaban en la ejecución
    anterior. Devuelve cuántos hallazgos "desaparecieron" (estaban antes y
    ya no aparecen — arreglados o ya no aplican)."""
    actuales = {reporte.fingerprint(f) for f in reporte.hallazgos}
    resueltos = len(huellas_previas - actuales)
    reporte.hallazgos = [f for f in reporte.hallazgos if reporte.fingerprint(f) not in huellas_previas]
    return resueltos


# ─── Salida SARIF (para GitHub code scanning / CI) ─────────────────────────────

def generar_sarif(reporte: Reporte, root: Path) -> str:
    nivel_sarif = {"CRITICO": "error", "ADVERTENCIA": "warning"}
    reglas_vistas = {}
    resultados = []
    for f in reporte.hallazgos:
        rule_id = f.categoria
        if rule_id not in reglas_vistas:
            reglas_vistas[rule_id] = CATEGORIA_TITULOS.get(rule_id, rule_id)
        resultados.append({
            "ruleId": rule_id,
            "level": nivel_sarif.get(f.severidad, "warning"),
            "message": {"text": f.detalle + (f" (MITRE ATT&CK: {f.mitre})" if f.mitre else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.ruta.replace(os.sep, "/")},
                    "region": {"startLine": f.linea if f.linea else 1},
                }
            }],
        })

    payload = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": PRODUCTO,
                    "version": VERSION,
                    "informationUri": URL_MARCA,
                    "rules": [{"id": rid, "name": rid, "shortDescription": {"text": titulo}}
                              for rid, titulo in reglas_vistas.items()],
                }
            },
            "results": resultados,
        }],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def generar_markdown(reporte: Reporte, root: Path) -> str:
    fecha = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    lineas = []
    lineas.append(f"# {PRODUCTO} — Informe de seguridad")
    lineas.append("")
    lineas.append(f"**{MARCA}** · {URL_MARCA}")
    lineas.append("")
    lineas.append(f"- **Ruta escaneada:** `{root}`")
    lineas.append(f"- **Fecha:** {fecha}")
    lineas.append(f"- **Críticos:** {len(reporte.criticos)}")
    lineas.append(f"- **Advertencias:** {len(reporte.advertencias)}")
    lineas.append("")

    if not reporte.hallazgos:
        lineas.append("## Sin hallazgos")
        lineas.append("")
        lineas.append("No se ha detectado ningún secreto, permiso peligroso ni fichero de hook inseguro.")
        return "\n".join(lineas)

    lineas.append("## Índice")
    lineas.append("")
    for cat in reporte.por_categoria:
        titulo = CATEGORIA_TITULOS.get(cat, cat)
        lineas.append(f"- [{titulo}](#{cat})")
    lineas.append("")

    for cat, items in reporte.por_categoria.items():
        titulo = CATEGORIA_TITULOS.get(cat, cat)
        lineas.append(f"## {titulo} {{#{cat}}}")
        lineas.append("")
        lineas.append("| Severidad | Ruta | Línea | Detalle | MITRE ATT&CK |")
        lineas.append("|---|---|---|---|---|")
        for f in sorted(items, key=lambda x: x.severidad != "CRITICO"):
            icono = "🔴" if f.severidad == "CRITICO" else "🟡"
            lineas.append(
                f"| {icono} {f.severidad} | `{f.ruta}` | {f.linea or '—'} | {f.detalle} | {f.mitre or '—'} |"
            )
        lineas.append("")

    return "\n".join(lineas)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>{producto} — Informe de seguridad</title>
<style>
  :root {{
    --bg: #0b0f19;
    --bg-panel: #121826;
    --bg-panel-2: #182034;
    --border: #232c40;
    --text: #e2e8f0;
    --text-dim: #8b96ab;
    --cyan: #22d3ee;
    --purple: #a855f7;
    --red: #f43f5e;
    --amber: #fbbf24;
    --green: #34d399;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: 'Segoe UI', Roboto, system-ui, sans-serif;
    background: radial-gradient(circle at top, #101728 0%, var(--bg) 60%);
    color: var(--text);
  }}
  header.brand {{
    padding: 26px 32px 22px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(120deg, rgba(34,211,238,0.08), rgba(168,85,247,0.08));
    display: flex;
    align-items: center;
    gap: 20px;
  }}
  header.brand .logo {{
    width: 56px;
    height: 56px;
    border-radius: 14px;
    object-fit: contain;
    background: var(--bg-panel);
    border: 1px solid var(--border);
    padding: 6px;
    flex-shrink: 0;
  }}
  header.brand .logo-fallback {{
    width: 56px;
    height: 56px;
    border-radius: 14px;
    background: linear-gradient(135deg, var(--cyan), var(--purple));
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
    font-size: 20px;
    color: #0b0f19;
    flex-shrink: 0;
  }}
  header.brand .titulo {{ flex: 1; min-width: 0; }}
  header.brand .tag {{
    color: var(--text-dim);
    font-size: 13px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }}
  header.brand h1 {{
    margin: 4px 0 6px;
    font-size: 28px;
    color: var(--text);
  }}
  header.brand .tag .accent {{
    color: var(--cyan);
    font-weight: 700;
  }}
  header.brand .barra {{
    height: 4px;
    width: 120px;
    border-radius: 999px;
    background: linear-gradient(90deg, var(--cyan), var(--purple));
    margin: 6px 0 10px;
  }}
  header.brand .meta {{
    color: var(--text-dim);
    font-size: 14px;
  }}
  nav.menu {{
    position: sticky;
    top: 0;
    z-index: 10;
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    padding: 10px 24px;
    background: rgba(11,15,25,0.92);
    backdrop-filter: blur(6px);
    border-bottom: 1px solid var(--border);
  }}
  nav.menu a {{
    color: var(--text-dim);
    text-decoration: none;
    font-size: 13px;
    padding: 8px 14px;
    border-radius: 8px;
    transition: all .15s ease;
  }}
  nav.menu a:hover {{
    color: var(--text);
    background: var(--bg-panel-2);
  }}
  main {{ padding: 28px 32px 60px; max-width: 980px; margin: 0 auto; }}
  section {{ margin-bottom: 36px; scroll-margin-top: 60px; }}
  section h2 {{
    font-size: 18px;
    margin-bottom: 14px;
    color: var(--text);
    border-left: 3px solid var(--cyan);
    padding-left: 10px;
  }}
  .cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 14px;
    margin-bottom: 6px;
  }}
  .card {{
    background: var(--bg-panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px 18px;
  }}
  .card .num {{ font-size: 28px; font-weight: 700; }}
  .card .lbl {{ font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: .05em; }}
  .card.critico .num {{ color: var(--red); }}
  .card.advertencia .num {{ color: var(--amber); }}
  .card.ok .num {{ color: var(--green); }}
  table {{
    width: 100%;
    table-layout: fixed;
    border-collapse: collapse;
    background: var(--bg-panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
    font-size: 13px;
  }}
  thead th {{
    text-align: left;
    background: var(--bg-panel-2);
    color: var(--text-dim);
    font-weight: 600;
    padding: 10px 10px;
    text-transform: uppercase;
    font-size: 10px;
    letter-spacing: .02em;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }}
  tbody td {{
    padding: 10px 10px;
    border-top: 1px solid var(--border);
    vertical-align: top;
    overflow-wrap: break-word;
    word-break: break-word;
    overflow: hidden;
  }}
  /* Severidad | Ruta | Línea | Detalle | MITRE — anchos fijos y generosos
     donde hace falta (la propia etiqueta "ADVERTENCIA" necesita sitio) más
     "overflow: hidden" como tope duro, para que ninguna celda invada nunca
     a la de al lado, ni en HTML ni en PDF */
  th:nth-child(1), td:nth-child(1) {{ width: 17%; }}
  th:nth-child(2), td:nth-child(2) {{ width: 13%; }}
  th:nth-child(3), td:nth-child(3) {{ width: 10%; }}
  th:nth-child(4), td:nth-child(4) {{ width: 32%; }}
  th:nth-child(5), td:nth-child(5) {{ width: 28%; }}
  tbody tr:hover {{ background: rgba(255,255,255,0.02); }}
  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: .01em;
  }}
  .badge.critico {{ background: rgba(244,63,94,0.15); color: var(--red); }}
  .badge.advertencia {{ background: rgba(251,191,36,0.15); color: var(--amber); }}
  code {{ color: var(--cyan); font-size: 12px; word-break: break-all; }}
  td.mitre {{ color: var(--purple); font-size: 12px; }}
  .ok-banner {{
    text-align: center;
    padding: 60px 20px;
    color: var(--green);
    font-size: 20px;
    font-weight: 700;
  }}
  footer {{
    text-align: center;
    padding: 24px;
    color: var(--text-dim);
    font-size: 12px;
    border-top: 1px solid var(--border);
  }}
  footer a {{ color: var(--cyan); text-decoration: none; }}
</style>
</head>
<body>
<header class="brand">
  {logo_html}
  <div class="titulo">
    <div class="tag">{marca} · <span class="accent">{producto}</span></div>
    <h1>Informe de seguridad</h1>
    <div class="barra"></div>
    <div class="meta">Ruta: <code>{root}</code> &nbsp;·&nbsp; Fecha: {fecha}</div>
  </div>
</header>
<nav class="menu">
  <a href="#resumen">Resumen</a>
  {menu_items}
</nav>
<main>
  <section id="resumen">
    <h2>Resumen</h2>
    <div class="cards">
      <div class="card critico"><div class="num">{n_criticos}</div><div class="lbl">Críticos</div></div>
      <div class="card advertencia"><div class="num">{n_advertencias}</div><div class="lbl">Advertencias</div></div>
      <div class="card ok"><div class="num">{n_total}</div><div class="lbl">Total hallazgos</div></div>
    </div>
  </section>
  {secciones}
</main>
<footer>
  Generado por <strong>{producto}</strong> — una herramienta de <a href="{url_marca}">{marca}</a>
</footer>
</body>
</html>
"""


def _logo_html(logo_path) -> str:
    """Devuelve el <img> del logo embebido en base64 (funciona en HTML y en el
    PDF de weasyprint sin depender de rutas externas), o un fallback con
    iniciales si no hay logo disponible."""
    candidato = logo_path or LOGO_PATH_DEFAULT
    if candidato and candidato.is_file():
        try:
            mime, _ = mimetypes.guess_type(str(candidato))
            mime = mime or "image/png"
            datos = base64.b64encode(candidato.read_bytes()).decode("ascii")
            return f'<img class="logo" src="data:{mime};base64,{datos}" alt="{_html_escape(MARCA)}">'
        except OSError:
            pass
    palabras = MARCA.replace("-", " ").split()
    iniciales = ((palabras[0][0] if palabras else "M") + (palabras[-1][0] if len(palabras) > 1 else "")).upper()
    return f'<div class="logo-fallback">{iniciales}</div>'


def _html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def generar_html(reporte: Reporte, root: Path, logo_path: Path = None) -> str:
    fecha = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")

    if not reporte.hallazgos:
        secciones = '<section id="ok"><div class="ok-banner">✔ Sin hallazgos. Todo limpio.</div></section>'
        menu_items = ""
    else:
        menu_items = "".join(
            f'<a href="#{cat}">{_html_escape(CATEGORIA_TITULOS.get(cat, cat))}</a>'
            for cat in reporte.por_categoria
        )
        bloques = []
        for cat, items in reporte.por_categoria.items():
            titulo = CATEGORIA_TITULOS.get(cat, cat)
            filas = []
            for f in sorted(items, key=lambda x: x.severidad != "CRITICO"):
                sev_clase = "critico" if f.severidad == "CRITICO" else "advertencia"
                filas.append(
                    f"<tr><td><span class='badge {sev_clase}'>{f.severidad}</span></td>"
                    f"<td><code>{_html_escape(f.ruta)}</code></td>"
                    f"<td>{f.linea or '—'}</td>"
                    f"<td>{_html_escape(f.detalle)}</td>"
                    f"<td class='mitre'>{_html_escape(f.mitre) if f.mitre else '—'}</td></tr>"
                )
            bloques.append(f"""
    <section id="{cat}">
      <h2>{_html_escape(titulo)}</h2>
      <table>
        <thead><tr><th>Severidad</th><th>Ruta</th><th title="Línea" style="text-transform:none">Línea</th><th>Detalle</th><th>MITRE ATT&amp;CK</th></tr></thead>
        <tbody>{''.join(filas)}</tbody>
      </table>
    </section>""")
        secciones = "".join(bloques)

    return HTML_TEMPLATE.format(
        producto=PRODUCTO,
        marca=MARCA,
        url_marca=URL_MARCA,
        root=_html_escape(str(root)),
        fecha=fecha,
        logo_html=_logo_html(logo_path),
        menu_items=menu_items,
        secciones=secciones,
        n_criticos=len(reporte.criticos),
        n_advertencias=len(reporte.advertencias),
        n_total=len(reporte.hallazgos),
    )


def generar_pdf(html_str: str, destino: Path) -> bool:
    """Intenta generar el PDF con weasyprint o xhtml2pdf, en ese orden.
    Devuelve True si lo consiguió, False si no hay ninguna librería disponible."""
    try:
        from weasyprint import HTML  # type: ignore
        HTML(string=html_str).write_pdf(str(destino))
        return True
    except ImportError:
        pass
    except Exception as e:
        print(f"{C.YELLOW}⚠ weasyprint falló al generar el PDF: {e}{C.RESET}")

    try:
        from xhtml2pdf import pisa  # type: ignore
        with open(destino, "wb") as f:
            resultado = pisa.CreatePDF(html_str, dest=f)
        return not resultado.err
    except ImportError:
        pass
    except Exception as e:
        print(f"{C.YELLOW}⚠ xhtml2pdf falló al generar el PDF: {e}{C.RESET}")

    return False


# ─── Exportación a fichero ──────────────────────────────────────────────────────

def exportar(reporte: Reporte, root: Path, formato: str, base_salida: Path, logo_path: Path = None) -> list:
    """Genera los ficheros pedidos. Devuelve la lista de rutas escritas."""
    generados = []
    vistos = set()
    html_cache = None

    def get_html():
        nonlocal html_cache
        if html_cache is None:
            html_cache = generar_html(reporte, root, logo_path)
        return html_cache

    if formato == "todos":
        formatos = ["md", "html", "pdf", "json"]
    elif formato == "pdf":
        # Pedir PDF también deja el HTML a mano (misma plantilla, sin pasos extra)
        formatos = ["html", "pdf"]
    else:
        formatos = [formato]

    def registrar(destino: Path):
        if destino not in vistos:
            vistos.add(destino)
            generados.append(destino)

    for f in formatos:
        if f == "md":
            destino = base_salida.with_suffix(".md")
            destino.write_text(generar_markdown(reporte, root), encoding="utf-8")
            registrar(destino)
        elif f == "html":
            destino = base_salida.with_suffix(".html")
            destino.write_text(get_html(), encoding="utf-8")
            registrar(destino)
        elif f == "pdf":
            destino = base_salida.with_suffix(".pdf")
            ok = generar_pdf(get_html(), destino)
            if ok:
                registrar(destino)
            else:
                # Fallback: deja el HTML igualmente para poder imprimirlo a PDF
                destino_html = base_salida.with_suffix(".html")
                destino_html.write_text(get_html(), encoding="utf-8")
                registrar(destino_html)
                print(
                    f"{C.YELLOW}⚠ No hay ninguna librería de PDF instalada "
                    f"(pip install weasyprint --break-system-packages).{C.RESET}\n"
                    f"  Se ha generado el HTML en su lugar: {destino_html}\n"
                    f"  Ábrelo y usa Ctrl/Cmd+P → 'Guardar como PDF' para obtener el PDF."
                )
        elif f == "json":
            destino = base_salida.with_suffix(".json")
            destino.write_text(generar_json(reporte, root), encoding="utf-8")
            registrar(destino)
        elif f == "sarif":
            destino = base_salida.with_suffix(".sarif")
            destino.write_text(generar_sarif(reporte, root), encoding="utf-8")
            registrar(destino)

    return generados


# ─── Menú interactivo ───────────────────────────────────────────────────────────

def listar_subcarpetas(base: Path) -> list:
    try:
        return sorted(
            [p for p in base.iterdir() if p.is_dir() and not p.name.startswith(".")],
            key=lambda p: p.name.lower(),
        )
    except OSError:
        return []


def _ancho_terminal(maximo=78, minimo=50):
    try:
        columnas = os.get_terminal_size().columns
    except OSError:
        columnas = 80
    return max(minimo, min(maximo, columnas - 2))


_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _longitud_visible(s: str) -> int:
    return len(_ANSI_RE.sub("", s))


def _caja_titulo(texto: str, color: str = None):
    color = color or C.CYAN
    ancho = _ancho_terminal()
    contenido = f" {C.BOLD}{texto}{C.RESET}"
    relleno = max(0, ancho - _longitud_visible(contenido))
    print(f"{color}╭{'─' * ancho}╮{C.RESET}")
    print(f"{color}│{C.RESET}{contenido}{' ' * relleno}{color}│{C.RESET}")
    print(f"{color}╰{'─' * ancho}╯{C.RESET}")


def elegir_carpeta(root_por_defecto: Path) -> Path:
    base = root_por_defecto
    primera_vuelta = True
    while True:
        subcarpetas = listar_subcarpetas(base)
        print()
        _caja_titulo(f"Carpeta actual: {base}" if primera_vuelta else f"{base}")
        primera_vuelta = False

        if subcarpetas:
            print(f"{C.DIM}  Elige qué escanear ({len(subcarpetas)} subcarpeta"
                  f"{'s' if len(subcarpetas) != 1 else ''} disponible"
                  f"{'s' if len(subcarpetas) != 1 else ''}):{C.RESET}\n")
            print(f"  {C.GREEN}{C.BOLD}[0]{C.RESET} {C.GREEN}> Escanear esta carpeta completa{C.RESET}"
                  f" {C.DIM}({base.name or base}){C.RESET}")
            print(f"  {C.DIM}{'-' * 40}{C.RESET}")
            for i, sub in enumerate(subcarpetas, start=1):
                numero = f"[{i}]".rjust(4)
                print(f"  {C.CYAN}{numero}{C.RESET} · {sub.name}/")
            print(f"  {C.DIM}{'-' * 40}{C.RESET}")
            print(f"  {C.MAGENTA}{C.BOLD}[m]{C.RESET} {C.MAGENTA}> Escribir otra ruta manualmente{C.RESET}\n")
        else:
            print(f"{C.DIM}  (sin subcarpetas — Enter para escanear esta ruta, "
                  f"o escribe otra){C.RESET}\n")

        entrada = input(f"  {C.BOLD}{C.CYAN}>{C.RESET} ").strip()

        if entrada == "" or entrada == "0":
            return base
        if entrada.lower() == "m":
            manual = input(f"  {C.MAGENTA}Ruta >{C.RESET} ").strip()
            if manual:
                return Path(manual).expanduser().resolve()
            continue
        if entrada.isdigit() and 1 <= int(entrada) <= len(subcarpetas):
            elegida = subcarpetas[int(entrada) - 1]
            # Permite entrar a un nivel más (útil si el proyecto tiene subcarpetas
            # propias) o escanear directamente pulsando "0" en el siguiente turno.
            base = elegida
            continue
        # Cualquier otra cosa: se interpreta como ruta escrita directamente
        return Path(entrada).expanduser().resolve()


def menu_interactivo(root_por_defecto: Path):
    root = elegir_carpeta(root_por_defecto.resolve())

    print()
    _caja_titulo("¿En qué formato quieres el informe?", color=C.MAGENTA)
    print()
    opciones = {
        "1": ("texto", "Solo en terminal (con colores)"),
        "2": ("md", "Markdown (.md)"),
        "3": ("html", "HTML con menú y colores (.html)"),
        "4": ("pdf", "PDF (.pdf)"),
        "5": ("json", "JSON (para n8n / CI)"),
        "6": ("todos", "Todos los formatos de fichero (md + html + pdf + json)"),
        "7": ("sarif", "SARIF (para GitHub code scanning)"),
    }
    for k, (_, desc) in opciones.items():
        print(f"  {C.CYAN}{C.BOLD}[{k}]{C.RESET} {desc}")
    print(f"\n  {C.DIM}(Enter = 1, solo terminal){C.RESET}")
    eleccion = input(f"\n  {C.BOLD}{C.CYAN}>{C.RESET} ").strip() or "1"
    formato = opciones.get(eleccion, opciones["1"])[0]

    return root, formato


# ─── Main ────────────────────────────────────────────────────────────────────────

def main():
    _preparar_color_terminal()
    parser = argparse.ArgumentParser(
        description=f"{PRODUCTO} — escáner de seguridad ligero para Claude Code / MCP ({MARCA})"
    )
    parser.add_argument("ruta", nargs="?", default=None, help="Directorio a escanear")
    parser.add_argument(
        "--formato",
        choices=["texto", "md", "html", "pdf", "json", "sarif", "todos"],
        default=None,
        help="Formato de salida. Si se omite, se muestra un menú interactivo.",
    )
    parser.add_argument("--json", action="store_true", help="Atajo de --formato json (compatibilidad)")
    parser.add_argument("--out", default=None, help="Nombre base de los ficheros generados (sin extensión)")
    parser.add_argument(
        "--logo",
        default=None,
        help="Ruta a tu logo (PNG/SVG) para el HTML/PDF. Por defecto busca "
             "'logo-menarguez-ia.png' junto al script; si no existe, usa un logo de respaldo con iniciales.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "warn"],
        default="critical",
        help="Nivel mínimo de severidad que provoca exit code != 0 (por defecto: critical)",
    )
    parser.add_argument("--sin-abrir", action="store_true", help="No abrir el HTML/PDF generado automáticamente")
    parser.add_argument(
        "--diff",
        nargs="?",
        const="",
        default=None,
        metavar="INFORME.json",
        help="Compara contra un informe JSON de una ejecución anterior y muestra solo los "
             "hallazgos NUEVOS. Sin ruta (solo '--diff'), busca automáticamente el último "
             "menarshield-informe-*.json dentro de la carpeta escaneada.",
    )
    parser.add_argument(
        "--sin-ignorar",
        action="store_true",
        help=f"No aplicar las reglas de {NOMBRE_IGNORE} aunque exista en la carpeta escaneada",
    )
    parser.add_argument("--version", action="store_true", help="Muestra la versión y sale")
    args = parser.parse_args()

    if args.version:
        print(f"{PRODUCTO} v{VERSION} ({VERSION_FECHA}) — {MARCA}")
        sys.exit(0)

    root_por_defecto = Path(args.ruta).expanduser().resolve() if args.ruta else Path(".").resolve()

    interactivo = args.formato is None and sys.stdin.isatty()

    if interactivo:
        imprimir_banner()
        root, formato = menu_interactivo(root_por_defecto)
    else:
        root = root_por_defecto
        formato = args.formato or "texto"

    if not root.exists():
        print(f"Ruta no encontrada: {root}", file=sys.stderr)
        sys.exit(2)

    reporte = Reporte()
    print(f"{C.DIM}Analizando {root}...{C.RESET}")
    archivos = list(iter_text_files(root, progreso=True))
    scan_secrets(root, reporte, archivos)
    scan_docker(root, reporte, archivos)
    scan_debug(root, reporte, archivos)
    scan_permissions(root, reporte)
    scan_hooks(root, reporte)
    scan_env_git(root, reporte)

    reporte.consolidar()

    if not args.sin_ignorar:
        reglas_ignoradas = cargar_reglas_ignoradas(root)
        n_ignorados = aplicar_ignorados(reporte, reglas_ignoradas)
        if n_ignorados:
            print(f"{C.DIM}({n_ignorados} hallazgo(s) omitido(s) por {NOMBRE_IGNORE}){C.RESET}")

    resueltos = None
    if args.diff is not None:
        ruta_diff = Path(args.diff).expanduser().resolve() if args.diff else None
        if ruta_diff is None or not ruta_diff.exists():
            # Sin ruta explícita: busca el último informe JSON dentro de la carpeta escaneada
            candidatos = sorted(root.glob("menarshield-informe-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            ruta_diff = candidatos[0] if candidatos else None
        if ruta_diff and ruta_diff.exists():
            huellas_previas = cargar_fingerprints_previos(ruta_diff)
            resueltos = aplicar_diff(reporte, huellas_previas)
            print(f"{C.DIM}Comparando contra {ruta_diff.name} — mostrando solo hallazgos nuevos "
                  f"({resueltos} ya no aparecen desde entonces){C.RESET}")
        else:
            print(f"{C.YELLOW}⚠ --diff: no se encontró un informe JSON anterior para comparar "
                  f"(usa --diff ruta/al/informe.json o genera primero uno con --formato json){C.RESET}")

    if not interactivo and formato not in ("texto",):
        imprimir_banner()

    if formato == "texto":
        if not interactivo:
            imprimir_banner()
        imprimir_texto(reporte, root)
    else:
        if args.out:
            # Ruta explícita: se respeta tal cual, relativa al directorio
            # desde el que se lanza el script (comportamiento de siempre).
            base_salida = Path(args.out).expanduser().resolve()
        else:
            # Por defecto, el informe se guarda DENTRO de la propia carpeta
            # escaneada — no de donde se lanzó "python3 menarshield.py" (que
            # normalmente es ~, y ahí es donde antes se colaba sin querer).
            # Esto también aplica a --formato json: así queda un fichero en
            # disco que --diff puede usar de base en la siguiente ejecución,
            # además de imprimirse por stdout para encadenar con n8n/CI.
            base_salida = root / f"menarshield-informe-{root.name or 'raiz'}"
        if formato == "json":
            imprimir_json_stdout(reporte, root)
        else:
            imprimir_texto(reporte, root)
            print()
        logo_path = Path(args.logo).expanduser().resolve() if args.logo else None
        generados = exportar(reporte, root, formato, base_salida, logo_path)
        for g in generados:
            print(f"{C.GREEN}✔ Generado:{C.RESET} {g}")
            if not args.sin_abrir and g.suffix in (".html", ".pdf") and interactivo:
                try:
                    webbrowser.open(g.as_uri())
                except Exception:
                    pass

    if reporte.criticos:
        sys.exit(2)
    if args.fail_on == "warn" and reporte.advertencias:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
