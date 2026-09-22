# MenarShield

Escáner de seguridad ligero, sin dependencias obligatorias, para configuraciones
de **Claude Code / MCP**, proyectos Docker/Docker Compose y repositorios en
general. Una herramienta de [Menarguez-IA Solutions](https://ai.menarguez-ia.com/).

Pensado para correr en local, en un homelab vía SSH, o en CI (GitHub Actions,
con salida SARIF nativa para el Security tab).

## Qué detecta

| Categoría | Ejemplos |
|---|---|
| Secretos hardcodeados | Tokens de Telegram, Supabase, GitHub, AWS, Anthropic/OpenAI, Stripe, JWT, claves PEM, y patrón genérico `VAR=valor-de-alta-entropía` |
| Permisos peligrosos en Claude Code | `settings.json` / `mcp.json` con allow-lists demasiado amplias (`Bash(*)`), `deny` vacío |
| Permisos de fichero inseguros | `hooks/` escribibles por grupo/otros, scripts `.sh` sin permiso de ejecución |
| Docker Compose / Dockerfile | `privileged: true`, `docker.sock` montado, `network_mode: host`, puertos en `0.0.0.0`, imágenes sin versión fijada (`:latest`), contenedor corriendo como root |
| Debug en producción | `Flask debug=True`, `FLASK_DEBUG=1`, `Django DEBUG=True`, ASP.NET Core `Development` |
| `.env` sin proteger | Repositorios git donde `.env` no está cubierto por `.gitignore` |

Cada hallazgo se anota, cuando aplica, con su técnica **MITRE ATT&CK** correspondiente.

Los almacenes de credenciales *esperados* (`.aws/credentials`, `.ssh/id_rsa`,
`.claude/.credentials.json`, `.npmrc`, `.docker/config.json`, etc.) no se
escanean por contenido — solo se avisa si tienen permisos de fichero
demasiado abiertos.

Los certificados **públicos y conocidos** (ej. los `.ovpn` de demostración
del servicio gratuito VPNBook, `vpnbook-*.ovpn`) se descartan por completo
— el mismo fichero, con el mismo contenido, lo tiene cualquiera. Esto es
un allowlist por *nombre exacto de fichero*, no por extensión: un `.ovpn`
con una clave privada real de tu propio Tailscale/OpenVPN/Wazuh se sigue
detectando con normalidad.

## Instalación

Solo requiere Python 3.9+ y la librería estándar. Todo lo demás es opcional:

```bash
pip install weasyprint pyyaml --break-system-packages   # PDF nativo + parseo YAML real de Docker Compose
```

Si `weasyprint` no está disponible, se usa `xhtml2pdf` como alternativa; si
ninguna está instalada, se genera igualmente el HTML y se explica cómo
imprimirlo a PDF desde el navegador.

## Uso

```bash
python3 menarshield.py                        # menú interactivo (elige ruta y formato)
python3 menarshield.py [ruta]                  # escanea y muestra menú de exportación
python3 menarshield.py [ruta] --formato html   # exporta directo, sin menú (para scripts/n8n/CI)
python3 menarshield.py [ruta] --formato md
python3 menarshield.py [ruta] --formato pdf    # genera también el .html de regalo
python3 menarshield.py [ruta] --formato json   # deja el .json en disco (sirve de base para --diff)
python3 menarshield.py [ruta] --formato sarif  # para GitHub Code Scanning / CI
python3 menarshield.py [ruta] --formato todos  # md + html + pdf + json de una vez

python3 menarshield.py [ruta] --diff            # solo hallazgos nuevos vs. el último JSON en esa carpeta
python3 menarshield.py [ruta] --diff otro.json  # diff contra un JSON concreto
python3 menarshield.py [ruta] --sin-ignorar     # ignora el fichero .menarshieldignore
python3 menarshield.py [ruta] --fail-on=warn    # exit code 1 también con warnings
python3 menarshield.py [ruta] --out mi-informe  # nombre base de los ficheros generados
python3 menarshield.py --version
```

### `.menarshieldignore`

Igual que un `.gitignore`: un patrón glob por línea, opcionalmente
`patrón:línea` para silenciar una línea exacta, `#` para comentarios. Se
aplica siempre salvo que se pase `--sin-ignorar`.

### Códigos de salida

| Código | Significado |
|---|---|
| `0` | Limpio |
| `1` | Solo warnings (si se usa `--fail-on=warn`) |
| `2` | Al menos un hallazgo crítico |

## Uso remoto (homelab / VM por SSH)

`menarshield-run.ps1` lanza el escaneo en una máquina remota por SSH y
descarga el informe generado a la carpeta local del proyecto:

```powershell
# una vez, para no tener que pasar -VmHost cada vez
setx MENARSHIELD_VM_HOST "usuario@tu-ip-o-hostname"

.\menarshield-run.ps1 -Ruta "~/mi-proyecto" -Formato pdf
.\menarshield-run.ps1 -Ruta "~/mi-proyecto" -Formato json -Diff
```

## CI: GitHub Actions

El workflow incluido en `.github/workflows/menarshield.yml` escanea el propio
repo en cada push/PR y semanalmente, sube los resultados al **Security tab**
de GitHub vía SARIF, y falla el job si hay hallazgos críticos.

## Licencia

Todos los derechos reservados — Menarguez-IA Solutions.
