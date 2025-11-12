### 1) Crear entorno e instalar dependencias
**Windows (PowerShell)**
```powershell // CMD
python -m venv .venv
pip install --upgrade pip

pip install -r requirements.txt
```

**macOS / Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2) Ejecutar la UI
```bash
# desde la raíz del proyecto
#set PYTHONPATH=. && python app/ChatBot.py        # Windows (CMD)
$env:PYTHONPATH='.'; python app/ChatBot.py       # Windows (PowerShell)
#PYTHONPATH=. python app/ChatBot.py               # macOS/Linux
```

### 3) Probar el ChatBot

#Se encuentra una carmeta 'eml', ahí contiene 3 archivos
- Phishing
- Sospechoso
- Legítimoo


////////////////////////////////////////////////////////

PySide6 se sustituye por Flask, pero solo en lo que respecta a la interfaz de usuario.
PySide6: Framework para crear aplicaciones de escritorio con GUI
Flask: MicroFramework web en Python, sirve para crear aplicaciones web, el backend que responde a solicitudes HTTP
El Server.py con Flask recibe los mensajes del usuario desde la web, llama a la logica de src/phishbot. 
Flask reemplaza la interfaz grafica de escritorio, pero la logica del chatbot y analisi sigue en src/phishbot. 

1. En la raiz del proyecto
2. Crear el entorno virtual y usarlo
python -m venv .venv
2.1 Opcional si no se activa 
.\.venv\Scripts\Activate.ps1
.\.venv\Scripts\python.exe --version
3. Activar pip 
.\.venv\Scripts\python.exe -m pip install --upgrade pip
4. Instalar dependencias desde requirements.txt
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
5. Ejecutar app/ChatBot.py con PYTHONPATH
.\.venv\Scripts\python.exe app/ChatBot.py
6. Ejecutar el servidor Flask (otro terminal)
.\.venv\Scripts\python.exe server.py
7. Debe aparecer: 
Archivo cargado correctamente ✅
Iniciando Flask...
 * Running on http://127.0.0.1:5000 -> En tu lap
 * Running on http://192.168.100.7:5000 -> En otros dispositivos conectados a la misma red
## Despliegue en Render

1. Crea un nuevo servicio Web en Render y conecta este repositorio (usa "New +" -> "Blueprint" para que tome render.yaml).
2. Render ejecutara pip install -r requirements.txt durante el build y luego iniciara gunicorn server:app, como se define en render.yaml y Procfile.
3. No es necesario exponer el puerto manualmente: el servidor ahora usa la variable PORT que Render inyecta y Gunicorn la consume automaticamente.
4. Agrega variables de entorno adicionales (tokens, banderas, etc.) desde el panel de Render o declaralas en render.yaml dentro de envVars.
5. Cada push a la rama conectada dispara un nuevo deploy; si necesitas pausar los despliegues automaticos, desactiva Auto-Deploy en la consola de Render.
