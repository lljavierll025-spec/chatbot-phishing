# server.py
import os
import sys
from pathlib import Path
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

# Ajuste de ruta para poder importar tu src como en la app desktop
_SRC_PATH = Path(__file__).resolve().parents[0] / "src"
if str(_SRC_PATH) not in sys.path:
    sys.path.append(str(_SRC_PATH))

# Intentamos importar los módulos reales; si fallan, usamos stubs para pruebas locales
try:
    from src.phishbot.nlu.chat_rules import nlu_detect, next_response, DialogueContext, Intent
except Exception as e:
    # Stubs / mocks para desarrollo local si src no está presente o falla la importación.
    # nlu_detect -> objeto simple con atributo 'intent'
    class _NLU:
        def __init__(self, intent=None):
            self.intent = intent
    def nlu_detect(text):
        return _NLU(intent=None)
    def next_response(text, ctx):
        # devuelve un reply simple y el mismo contexto
        return (f"Respuesta simulada: recibí '{text}'", ctx)
    class DialogueContext:
        def __init__(self):
            pass
    class Intent:
        ANALISIS_PETICION = None

try:
    from src.phishbot.analyzers.phishing_analyzer import analyze_eml_hybrid
except Exception:
    analyze_eml_hybrid = None  # Si no existe, el endpoint de análisis responderá con error

# Flask app
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB
UPLOAD_FOLDER = Path("uploads")
UPLOAD_FOLDER.mkdir(exist_ok=True)
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)

# Contexto único (para pruebas; en producción mapear por sesión)
CTX = DialogueContext()

# Función para formatear el resultado híbrido (precaución con comillas)
def format_hybrid_result(r: dict) -> str:
    nivel = r.get('nivel', '')
    prediccion = r.get('prediccion', '')
    score = r.get('score_final', 0)
    prob = r.get('prob_modelo', 0)
    umbral = r.get('umbral_modelo', 0)

    color_map = {'rojo': '#ef4444', 'amarillo': '#f59e0b', 'verde': '#10b981'}
    color = color_map.get(nivel, '#6b7280')
    level_text = {'rojo': 'Riesgo alto', 'amarillo': 'Requiere atención', 'verde': 'Sin hallazgos'}.get(nivel, str(nivel).capitalize() if nivel else 'Resultado')
    level_icon = {'rojo': '🔴', 'amarillo': '🟡', 'verde': '🟢'}.get(nivel, '')
    title_text = f"{level_icon} {level_text}".strip()

    resumen = r.get("resumen", {}) or {}
    dominios = resumen.get("dominios_enlaces", []) or []
    enlaces_html = resumen.get("enlaces_html", []) or dominios
    enlaces_detalle = resumen.get("enlaces_detalle", []) or []
    if enlaces_detalle:
        enlaces_list = enlaces_detalle[:5]
    elif enlaces_html:
        enlaces_list = enlaces_html[:5]
    else:
        enlaces_list = []

    razones = r.get("explicacion", []) or []
    if not razones:
        razones = ["No encontramos señales graves, pero permanece atento."]

    user_copy = {
        'rojo': {
            "headline": "Es muy probable que sea phishing.",
            "tips": [
                "No abras enlaces ni adjuntos.",
                "Contacta al remitente por un canal oficial antes de responder.",
                "Reporta el correo a tu equipo de seguridad o proveedor."
            ]
        },
        'amarillo': {
            "headline": "No se encontraron señales claras de intento de phishing.",
            "tips": [
                "Verifica la información entrando manualmente al sitio legítimo.",
                "Responde solo si confirmas que proviene de la organización real."
            ]
        },
        'verde': {
            "headline": "No detectamos riesgos claros.",
            "tips": [
                "Aun así, evita compartir contraseñas o códigos por correo.",
                "Ante cualquier duda, confirma por un canal oficial."
            ]
        }
    }
    copy = user_copy.get(nivel, user_copy['amarillo'])

    html = f"""
    <div style="background-color: #f9fafb; padding: 15px; border-radius: 8px; border-left: 4px solid {color};">
        <h3 style="margin: 0 0 6px 0; color: {color};">
            {title_text} · {prediccion}
        </h3>
        <p style="margin: 0; color: #1f2937; font-size: 14px;">
            {copy['headline']}
        </p>
    </div>
    <div style="margin-top: 14px;">
        <b>Señales</b>
        <ul style="padding-left: 20px; margin: 6px 0 0 0;">
    """
    for razon in razones:
        html += f"<li>{razon}</li>"
    html += "</ul></div>"

    html += """
    <div style="margin-top: 14px;">
        <b>Enlaces detectados:</b>
        <ul style="padding-left: 20px; margin: 6px 0 0 0; color: #111827;">
    """
    if enlaces_list:
        for entry in enlaces_list:
            if isinstance(entry, dict):
                href = entry.get("href", "—")
                text = entry.get("text") or href
            else:
                href = text = entry
            display = text if text != href else href
            html += f'<li style="color: #111827;">{display}</li>'
    else:
        html += "<li>No encontramos enlaces.</li>"

    html += f"""
        </ul>
    </div>
    <div style="background-color: #eef2ff; padding: 12px; border-radius: 8px; border-left: 3px solid {color}; margin-top: 14px;">
        <b>Próximos pasos sugeridos:</b>
        <ul style="padding-left: 20px; margin: 6px 0 0 0;">
    """
    for tip in copy["tips"]:
        html += f"<li>{tip}</li>"
    html += "</ul></div>"

    return html

# --- Rutas ---
@app.route("/")
def index():
    # intenta renderizar templates/index.html; si no existe, devuelve HTML mínimo para pruebas
    try:
        return render_template("index.html")
    except Exception:
        return "<h1>ChatBot - servidor Flask activo ✅</h1><p>Crea templates/index.html para la interfaz.</p>"

@app.route("/api/message", methods=["POST"])
def api_message():
    """Recibe texto del usuario, devuelve respuesta del bot en HTML y bandera de despedida."""
    data = request.json or {}
    user_text = (data.get("text") or data.get("message") or "").strip()
    if not user_text:
        return jsonify({"ok": False, "error": "Sin texto"}), 400

    # Detección de intención y respuesta (usa funciones reales si se importaron)
    nlu = nlu_detect(user_text)
    global CTX
    reply, new_ctx = next_response(user_text, CTX)
    CTX = new_ctx

    # Formatear respuesta (reemplazar saltos por <br>)
    reply_html = reply.replace("\n", "<br>") if isinstance(reply, str) else str(reply)

    # Detectar despedida
    goodbye_words = [
        'adios', 'adiós', 'chao', 'chau', 'bye', 'salir',
        'exit', 'quit', 'hasta luego', 'nos vemos', 'gracias adios',
        'hasta pronto', 'me voy'
    ]
    text_lower = user_text.lower().strip()
    is_goodbye = any(word in text_lower for word in goodbye_words)

    return jsonify({"ok": True, "reply": reply_html, "is_goodbye": is_goodbye, "intent": getattr(nlu, "intent", None)})

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Recibe archivo .eml (form-data) y devuelve HTML formateado con resultado."""
    if analyze_eml_hybrid is None:
        return jsonify({"ok": False, "error": "El módulo de análisis no está disponible en el servidor."}), 500

    if 'file' not in request.files:
        return jsonify({"ok": False, "error": "No se recibió archivo."}), 400

    f = request.files['file']
    filename = secure_filename(f.filename)
    save_path = Path(app.config['UPLOAD_FOLDER']) / filename
    f.save(save_path)

    try:
        result = analyze_eml_hybrid(str(save_path))
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    finally:
        try:
            save_path.unlink()  # opcional: borrar archivo
        except Exception:
            pass

    html = format_hybrid_result(result)
    return jsonify({"ok": True, "html": html, "raw": result})

# Punto de entrada correcto
if __name__ == "__main__":
    # Mensajes útiles para depuración
    print("Archivo cargado correctamente ✅")
    print("Iniciando Flask...")
    port = int(os.environ.get('PORT', 5000))
    debug_enabled = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug_enabled, host='0.0.0.0', port=port)
