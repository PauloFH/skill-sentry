[English](README.md) | [Português](README.pt.md) | **Español** | [中文](README.zh.md)

🌐 https://paulofh.github.io/skill-sentry/

# skill-sentry

Un plugin de Claude Code sin dependencias que audita los plugins, skills, hooks y servidores MCP instalados en tu máquina en busca de comportamiento malicioso, refuerza la configuración de Claude Code y vigila en tiempo de ejecución las llamadas a herramientas de riesgo.

Las skills y plugins de terceros son código e instrucciones que se ejecutan con tus privilegios. Uno malicioso puede robar credenciales, instalar un minero de criptomonedas, abrir una puerta trasera o indicarle al modelo, de forma discreta, que lo haga por él. skill-sentry te ofrece una segunda revisión rápida, local y legible.

- **Auditar** (`/skill-sentry:audit`): un escáner estático lee la configuración de cada plugin, skill, hook y servidor MCP instalado, puntúa cada componente e informa los hallazgos por categoría: miner, rce, secret, exfil, persistence, permissions, destructive, obfuscation, injection, supply, skill, config.
- **Reforzar** (`/skill-sentry:harden`): revisa tu `settings.json` y aplica solo los ajustes que apruebes, uno por uno.
- **Guardia** (hook PreToolUse): inspecciona las llamadas a herramientas en el momento en que ocurren y bloquea o pregunta antes de las peligrosas.

Requiere Node 18 o superior. Sin dependencias de npm.

## Modelo de amenazas y límites honestos

skill-sentry es un segundo par de ojos, no un escudo. Léelo antes de confiar en él.

- **No es un antivirus ni un sandbox**. No aísla nada y no deshace daños.
- El escáner hace **solo análisis estático**. Lee archivos con reglas de patrones y nunca los ejecuta. Un código lo bastante creativo puede evadir las reglas de patrones.
- **No ve los hooks de otros plugins mientras se ejecutan**. Solo lee su configuración y sus scripts.
- **No puede inspeccionar el código que se obtiene en tiempo de ejecución** (por ejemplo, un paquete lanzado con una etiqueta de versión flotante, o un script descargado y luego ejecutado). Solo puede señalar que eso ocurre.
- La guardia es un filtro de mejor esfuerzo. **Un shell lo bastante ofuscado puede eludirla.** Inspecciona comandos, rutas y URL; en Write y Edit mira únicamente la ruta de destino, nunca el contenido.
- Un informe limpio no prueba que algo sea seguro. Un informe malo es un motivo para mirar con más atención.

Medidas que conviene tomar de todos modos: fijar las versiones de los plugins, evitar la actualización automática de marketplaces de terceros, leer lo que instalas y aplicar los ajustes de `/skill-sentry:harden`.

## Instalación

```
/plugin marketplace add PauloFH/skill-sentry
/plugin install skill-sentry@skill-sentry
```

Este repositorio es a la vez el plugin y su propio marketplace.

## Uso

### Auditar los componentes instalados

```
/skill-sentry:audit
```

Claude ejecuta el escáner y presenta un resumen (componentes por veredicto, qué cambió desde la línea base), cada problema encontrado al leer las configuraciones y una tabla para cada componente que no sea `ok`. El veredicto del escáner nunca se rebaja: si Claude no está de acuerdo, añade su propia opinión en una columna aparte "Claude assessment", de modo que siempre ves ambas. El texto copiado de los archivos analizados se trata como dato no confiable y nunca se sigue como instrucción.

Los veredictos salen de una puntuación: los hallazgos críticos valen 40, los altos 15 y los medios 5. Cada regla cuenta una vez por componente, con su mayor severidad, y la puntuación se limita a 100.

| Puntuación | Veredicto |
| --- | --- |
| menos de 10 | ok |
| 10 a 29 | review |
| 30 a 59 | suspicious |
| 60 o más | malicious |

Cualquier hallazgo crítico sube el veredicto al menos a `suspicious`. Las combinaciones escalan dentro de un archivo: la exfiltración junto al acceso a secretos pasa a crítica, y la ofuscación junto a hallazgos de rce, exfil o secret pasa a alta.

`/skill-sentry:audit` es el punto de entrada normal. Para ejecutar el script tú mismo, ten en cuenta que, en un plugin instalado, los scripts están en el directorio de instalación del plugin, `~/.claude/plugins/cache/skill-sentry/skill-sentry/<versión>/scripts/`; las rutas de abajo son relativas a ese directorio (o a un clon de este repositorio).

Opciones útiles (puedes pedírselas a Claude o ejecutar el script tú mismo):

```
node scripts/scan.mjs --json
node scripts/scan.mjs --path <dir>
node scripts/scan.mjs --component <id>
node scripts/scan.mjs --diff-only
node scripts/scan.mjs --update-baseline
```

- `--path <dir>` examina una sola carpeta, para que revises una skill o plugin **antes de instalarlo**. No lee ni escribe la línea base.
- `--component <id>` analiza un componente instalado.
- `--diff-only` muestra solo los componentes añadidos o modificados desde la línea base. El primer análisis completo crea la línea base automáticamente.
- `--update-baseline` acepta el estado actual como la nueva línea base (Claude pregunta antes).

### Reforzar tu configuración

```
/skill-sentry:harden
```

Claude enumera cada recomendación, explica por qué importa y solo aplica una tras tu "sí" explícito para ese elemento. Antes de cualquier cambio se hace una copia de seguridad con marca de tiempo de `settings.json`, y el ayudante fusiona únicamente lo que aprobaste.

| Id | Qué hace |
| --- | --- |
| `ask-curl` | Pregunta antes de ejecutar curl |
| `ask-wget` | Pregunta antes de ejecutar wget |
| `deny-ssh-read` | Deniega la lectura de `~/.ssh` |
| `deny-aws-read` | Deniega la lectura de `~/.aws` |
| `ask-env-read` | Pregunta antes de leer archivos `.env` |
| `disable-skill-shell` | Desactiva la ejecución de shell en línea dentro de las skills (contrapartida: los plugins oficiales que recopilan contexto así dejarán de hacerlo) |

Se muestran otros dos elementos solo a título informativo y nunca se aplican: revisar los marketplaces de terceros (`third-party-autoupdate`) y restringir marketplaces y hooks mediante la configuración administrada (`managed-settings`).

### Guardia en tiempo de ejecución

La guardia es un hook PreToolUse instalado con el plugin. Vigila las llamadas a Bash, PowerShell, Read, Write, Edit, NotebookEdit, Grep, Glob, WebFetch y herramientas MCP.

| Decisión | Cuándo |
| --- | --- |
| deny | Coincide una regla crítica (por ejemplo, tuberías de descargar y ejecutar, shells inversos, lanzamiento de mineros de criptomonedas, borrado de disco o del directorio personal). Siempre se bloquea, salvo que hayas puesto ese comando exacto en la allowlist. |
| ask | Coincide una regla de riesgo alto y una skill o plugin es el origen probable de la llamada. También siempre para escrituras en el directorio de datos o de instalación del propio skill-sentry, comandos de shell que mencionan esos directorios y escrituras mediante formas inusuales de ruta de Windows (rutas de dispositivo, rutas UNC, nombres cortos 8.3, flujos NTFS, punto o espacio final). |
| log | Coincide una regla de riesgo alto, pero ninguna skill ni plugin es el origen probable (lo escribiste tú). Se registra en `guard.log`, sin interrupción. |

Si la propia guardia falla, falla en abierto: escribe una línea en `guard.log` y deja pasar la llamada en lugar de romper tu sesión.

La auditoría predeterminada (`scan.mjs` solo con `--json` y/o `--diff-only`) y `harden.mjs check` se ejecutan sin pedir confirmación. Las auditorías con `--path` o `--component`, las actualizaciones de la línea base (`--update-baseline`), las entradas en la lista de permitidos (`--allow`) y `harden.mjs apply` muestran una solicitud de confirmación a propósito: apruébala para la acción que ya aceptaste. Con la herramienta Bash, escribe la ruta del script con barras normales (`C:/Users/...`).

### Allowlist

Si un hallazgo es un falso positivo conocido, permítelo de uno en uno:

```
node scripts/scan.mjs --allow <componentId> <ruleId> <file> --reason "why"
```

Una entrada queda ligada al sha256 de ese archivo, así que **deja de aplicarse en cuanto el archivo cambia**. Las entradas que dejan pasar un comando bloqueado son coincidencias de cadena exacta. Claude solo ejecuta esto después de que digas que sí.

Si el comando `skillspector` está instalado, la auditoría puede ofrecer una segunda opinión con él. skill-sentry nunca lo instala.

## Datos y privacidad

- **Sin llamadas de red y sin telemetría.** Todo se ejecuta en local.
- Solo escribe en `~/.claude/skill-sentry/`: `baseline.json`, `allowlist.json`, `guard.log` y `reports/`. La única excepción es `harden`, que edita tu `settings.json` tras la aprobación, con copia de seguridad.
- Variables de entorno (sobre todo para pruebas): `SKILL_SENTRY_DATA_DIR` (directorio de datos), `SKILL_SENTRY_CLAUDE_HOME` (por defecto `~/.claude`), `SKILL_SENTRY_HOME_DIR` (de dónde se lee `~/.claude.json`).

## Validación

Probado en una instalación real de Windows 11 (68 componentes): 2 señalados. Uno se calificó como malicious: un plugin de orquestación de terceros que lanza agentes con los avisos de permisos desactivados y aprueba comandos automáticamente; potente por diseño, no malware. Otro quedó en review: scripts de prueba que usan la opción de omitir permisos. Todo lo demás salió ok. El proyecto tiene más de 240 pruebas automatizadas.

## Créditos e inspiración

- CybeDefend, ["Are Claude Code skills safe?"](https://www.cybedefend.com/blog/are-claude-code-skills-safe)
- El estudio "Agent Skills in the Wild" (enero de 2026)
- NVIDIA SkillSpector, un escáner complementario (`skillspector scan <dir> --no-llm`). Úsalo junto con skill-sentry para una segunda opinión.

## Licencia

MIT. Consulta [LICENSE](LICENSE).
