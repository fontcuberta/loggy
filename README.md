# Loggy

Analizador local de logs de Cisco y FortiGate. Lees archivos o recibes syslog, y Loggy ordena cada evento por tiempo, marca lo crítico que es y propone qué hacer. La interfaz está en español.

Los logs no salen del equipo. La web y el receptor syslog escuchan solo en `127.0.0.1`. El almacén es una base SQLite en disco. El único modelo permitido es Ollama en localhost; una URL externa se rechaza.

## Qué hace

- Ingesta por archivos (varios `.log` o `.txt` a la vez) y por syslog UDP y TCP.
- Normaliza cada línea: timestamp, dispositivo, fabricante, severidad, mensaje, campos y la línea original.
- Ordena la línea de tiempo. Si el log no trae año, usa el año actual y lo marca como estimado.
- Criticidad: Crítico, Alto, Medio, Bajo o Informativo. Sale de la severidad del equipo (Cisco 0–7, FortiGate `level`). Una base de firmas puede subir ese piso, por ejemplo una interfaz caída, un fallo de login, un cambio de configuración, un IPS no bloqueado o malware.
- Cada evento muestra una explicación, una causa probable y acciones recomendadas.
- Tres motores, en Ajustes:
  - **Reglas locales.** Offline. No llama a ningún modelo.
  - **Modelo local.** Ollama redacta la explicación y las acciones. La criticidad la siguen fijando las reglas.
  - **Híbrido** (por defecto). Las reglas deciden y Ollama solo amplía el texto. Si Ollama no responde, se quedan las reglas y la interfaz lo avisa.

Formatos de esta versión: Cisco IOS, IOS-XE y ASA (`%FACILITY-SEVERITY-MNEMONIC:`), y FortiGate en clave=valor (`date`, `time`, `devname`, `type`, `subtype`, `level`, `logid`, `action`, `msg`). Lo que no encaja se guarda igual, marcado como no reconocido.

Las firmas y las acciones editables están en [backend/app/knowledge/signatures.yaml](backend/app/knowledge/signatures.yaml).

## Cómo usarla

1. Abre la interfaz (por defecto [http://127.0.0.1:5173](http://127.0.0.1:5173)).
2. Suelta archivos de log o pulsa **Elegir archivos**.
3. Filtra por criticidad, fabricante, dispositivo o texto. Al abrir un evento ves la línea original, los campos, la explicación y los pasos.
4. En **Ajustes** cambias el motor, la URL de Ollama (`http://127.0.0.1:11434`), el modelo (`llama3.1:8b`) y la zona horaria de los logs que no traen zona. También puedes borrar todos los datos locales.

El syslog en vivo escucha en `127.0.0.1:5514` (UDP y TCP). El puerto 514 en macOS pide privilegios de administrador; 5514 no. Un firewall de otra máquina no puede enviar logs directos a este puerto: exporta el archivo o reenvía el syslog por un túnel SSH hacia `127.0.0.1:5514`.

Para usar el modelo local:

```bash
ollama serve
ollama pull llama3.1:8b
```

Sin Ollama, el modo híbrido y el de reglas siguen funcionando.

## Instalación manual

Hacen falta Python 3.9+ y Node.js 18+.

Terminal 1, API:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m app.main
```

La API queda en [http://127.0.0.1:8000](http://127.0.0.1:8000). Los datos se guardan en `backend/data/loggy.db`, que no se sube a git.

Terminal 2, interfaz:

```bash
cd frontend
npm install
npm run dev
```

Vite sirve la interfaz en [http://127.0.0.1:5173](http://127.0.0.1:5173) y reenvía `/api` al backend. Si el 5173 está ocupado, Vite imprime otro puerto.

Pruebas del backend:

```bash
cd backend
source .venv/bin/activate
pytest -q
```

## Pedirle a una IA que lo instale y lo arranque

Copia uno de estos textos en Cursor, u otro asistente con acceso a la terminal, con el proyecto abierto o después de clonar el repo.

### Instalar y arrancar

```text
Instala y arranca Loggy en este equipo, sin exponerlo a la red.

Repo: https://github.com/fontcuberta/loggy.git
Si aún no está clonado, clónalo y entra en la carpeta.

1. En backend/, crea un virtualenv con python3 -m venv .venv, actívalo e instala backend/requirements.txt.
2. Arranca la API con python -m app.main desde backend/. Tiene que escuchar solo en 127.0.0.1:8000.
3. En frontend/, ejecuta npm install y npm run dev. La interfaz debe quedar en 127.0.0.1 (puerto 5173, o el que imprima Vite si ese está ocupado).
4. Comprueba que http://127.0.0.1:8000/api/health responde {"ok": true} y que la interfaz carga.
5. No cambies el bind a 0.0.0.0. No configures ningún modelo que no sea localhost.
6. Al terminar, dime las dos URLs, cómo parar los procesos y que Ollama es opcional (ollama serve y ollama pull llama3.1:8b). Si Ollama no está, déjalo en modo híbrido: las reglas locales siguen analizando.
```

### Solo arrancar, si ya está instalado

```text
Arranca Loggy, que ya está instalado en este repo.

1. Desde backend/, con el virtualenv .venv activado, ejecuta python -m app.main. Solo 127.0.0.1:8000.
2. Desde frontend/, ejecuta npm run dev y quédate con el puerto local que imprima.
3. Confirma /api/health y que la página abre.
4. No reinstales dependencias si ya están. No abras el servicio a otras interfaces de red.
5. Dime las URLs locales para abrir la interfaz y para enviar syslog (127.0.0.1:5514, UDP y TCP).
```

### Comprobar que analiza un log

```text
Con Loggy ya arrancado en local, comprueba el análisis sin usar un modelo en la nube.

1. Crea un archivo temporal con estas dos líneas y súbelo a POST http://127.0.0.1:8000/api/upload como campo files:
   Sep 23 18:10:01.123: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
   date=2024-09-23 time=18:12:00 devname="FGT-HQ" tz="+0200" type="utm" subtype="virus" level="alert" action="blocked" msg="malware blocked"
2. Llama a GET http://127.0.0.1:8000/api/events y confirma que hay una interfaz caída de Cisco y un malware de FortiGate, con criticidad y acciones.
3. Borra el archivo temporal. No borres la base salvo que te lo pida: si hace falta dejarla limpia, usa POST http://127.0.0.1:8000/api/purge.
4. Dime los títulos, la criticidad y si Ollama participó o se usaron solo las reglas.
```
