# -*- coding: utf-8 -*-
"""
chatbot_edu_phishing_rules.py — V1.2

Mejoras en esta versión:
- Detección mejorada de conceptos individuales: "2fa", "mfa", "ingeniería social"
- Mensaje de despedida integrado
- Mejor normalización de términos con tildes
- Prioridad aumentada para términos escritos solos
"""

from __future__ import annotations
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple


# ========== Normalización ==========
def normalize(text: str) -> str:
    text = text.lower().strip()
    text = "".join(
        c for c in unicodedata.normalize("NFD", text)
        if unicodedata.category(c) != "Mn"
    )
    text = re.sub(r"\s+", " ", text)
    return text


# ========== Intenciones/Estados ==========
class Intent(str, Enum):
    DEFINICION = "definicion_concepto"
    SENALES = "senales_comunes"
    BP_GENERALES = "buenas_practicas_generales"
    BP_ESPECIFICAS = "buenas_practicas_especificas"
    TERMINOLOGIA = "terminologia_email_segura"
    SALUDO_MENU = "saludo_menu_educativo"
    DESPEDIDA = "despedida"
    DESAMBIG = "desambiguacion"
    FUERA = "fuera_de_ambito"
    ANALISIS_PETICION = "analisis_pase_externo"


class State(str, Enum):
    INICIO = "inicio"
    MENU_EDU = "menu_educativo"
    EXPLICACION = "explicacion_concepto"
    CHECKLIST = "checklist_consejos"
    DESAMBIG = "desambiguacion"
    FINALIZADO = "finalizado"


# ========== Prioridades ==========
INTENT_PRIORITY: Dict[Intent, int] = {
    Intent.DEFINICION: 5,
    Intent.SENALES: 5,
    Intent.BP_ESPECIFICAS: 5,
    Intent.BP_GENERALES: 4,
    Intent.TERMINOLOGIA: 5,
    Intent.SALUDO_MENU: 2,
    Intent.DESPEDIDA: 6,
    Intent.FUERA: 1,
    Intent.ANALISIS_PETICION: 6,
}
DESAMBIG_MARGIN = 0.15

# ========== Disparadores ==========
ANALISIS_KEYWORDS = [
    r"\banaliza(r)?\b", r"\brevisa(r)?\b", r"\bevalua(r)?\b",
    r"\bveredicto\b", r"\beste correo\b", r"\bmi correo\b", r"\bmensaje adjunto\b"
]

SALUDO_KEYWORDS = [
    "hola", "buenas", "que puedes hacer", "ayuda", "menu", "opciones"
]

DESPEDIDA_KEYWORDS = [
    "adios", "chao", "chau", "bye", "salir", "exit", "quit",
    "hasta luego", "nos vemos", "hasta pronto", "me voy"
]

SENALES_KEYWORDS = [
    "senales phishing", "senales", "senales comunes",
    "como identificar", "pistas", "red flags",
    "como detectar", "indicadores phishing", "alertas phishing"
]

BP_GENERALES_KEYWORDS = [
    "consejos", "buenas practicas", "recomendaciones", "como prevenir",
    "prevencion phishing", "que hacer", "buenas practicas correo"
]

BP_SUBTOPICS = {
    "enlaces": ["enlace", "link", "url", "acortador", "bit.ly", "tinyurl", "redirigir", "dominio"],
    "contrasenas": ["contrasena", "password", "gestor", "pass", "reutilizar", "fortaleza"],
    "2fa": ["2fa", "mfa", "doble factor", "autenticacion"],
    "adjuntos": ["adjunto", "archivo", ".zip", ".exe", "macro", "documento"],
    "qr": ["qr", "codigo qr", "quishing"],
}

TERMINOLOGIA_TERMS = [
    "spf", "dkim", "dmarc", "reply-to", "return-path",
    "homografos", "display name", "cabeceras", "encabezados"
]

# \U0001F449 Lista ampliada de conceptos que cuando se escriben solos dan definición
CONCEPT_KEYWORDS = [
    "phishing", "smishing", "vishing", "bec",
    "ingenieria social", "ingenieria",
    "2fa", "mfa",
    "autenticacion", "autenticacion dos factores",
    "doble factor", "doble autenticacion",
    "return path", "return-path",
    "reply to", "reply-to"
]

DEFINICION_PATTERNS = [
    r"que es (?P<term>.+)",
    r"que significa (?P<term>.+)",
    r"definicion (?P<term>.+)",
    r"explica(?:r)? (?P<term>.+)",
    r"explicacion de (?P<term>.+)",
    r"diferencia entre (?P<term>.+?) y (?P<term2>.+)",
    r"comparacion (?P<term>.+?) vs (?P<term2>.+)"
]


# ========== Estructuras ==========
@dataclass
class NLUResult:
    intent: Intent
    score: float
    slots: Dict[str, str]
    alt: Optional[Tuple[Intent, float]] = None


# ========== Utilidades NLU ==========
def any_regex_match(text: str, patterns: List[str]) -> bool:
    return any(re.search(p, text) for p in patterns)


def count_hits(text: str, keywords: List[str]) -> int:
    return sum(1 for kw in keywords if kw in text)


def detect_bp_subtopic(text: str) -> Optional[str]:
    for sub, kws in BP_SUBTOPICS.items():
        if count_hits(text, kws) > 0:
            return sub
    return None


def extract_definition_term(text: str) -> Dict[str, str]:
    for pat in DEFINICION_PATTERNS:
        m = re.search(pat, text)
        if m:
            d = {k: v.strip() for k, v in m.groupdict().items() if v}
            for k in list(d.keys()):
                d[k] = re.sub(r"[\?\.\!]+$", "", d[k])
            return d
    return {}


# ========== Motor NLU ==========
def nlu_detect(text_raw: str) -> NLUResult:
    text = normalize(text_raw)

    # 0) Despedida
    if count_hits(text, DESPEDIDA_KEYWORDS) > 0:
        return NLUResult(Intent.DESPEDIDA, 1.0, {})

    # 1) Puente a análisis
    if any_regex_match(text, ANALISIS_KEYWORDS):
        return NLUResult(Intent.ANALISIS_PETICION, 1.0, {})

    candidates: List[Tuple[Intent, float, Dict[str, str]]] = []

    # 2) Definición por pregunta explícita
    slots = extract_definition_term(text)
    if slots:
        score = 0.6
        term_norm = normalize(slots.get("term", "") + " " + slots.get("term2", ""))
        if any(t in term_norm for t in TERMINOLOGIA_TERMS + CONCEPT_KEYWORDS):
            score += 0.2
        candidates.append((Intent.DEFINICION, score, slots))

    # 3) \U0001F525 Definición al escribir SOLO el término (mejorado)
    # Verifica si el texto es prácticamente solo un concepto
    text_clean = re.sub(r'[^\w\s]', '', text).strip()
    words = text_clean.split()

    # Si es 1-3 palabras, buscar coincidencia exacta con conceptos
    if len(words) <= 3:
        for concept in CONCEPT_KEYWORDS:
            concept_words = concept.split()
            # Coincidencia exacta o muy cercana
            if text_clean == concept or all(w in text_clean for w in concept_words):
                candidates.append((Intent.DEFINICION, 0.85, {"term": concept}))
                break

    # También buscar conceptos clave dentro de texto más largo
    for concept in CONCEPT_KEYWORDS:
        # Buscar el concepto como palabra completa
        if re.search(rf'\b{re.escape(concept)}\b', text):
            # Solo si no detectamos otros patrones fuertes
            if len(candidates) == 0 or candidates[0][1] < 0.7:
                candidates.append((Intent.DEFINICION, 0.65, {"term": concept}))
                break

    # 4) Terminología técnica
    term_hits = count_hits(text, TERMINOLOGIA_TERMS)
    if term_hits > 0:
        candidates.append((Intent.TERMINOLOGIA, 0.55 + 0.05 * min(term_hits, 3), {}))

    # 5) Señales comunes
    s_hits = count_hits(text, SENALES_KEYWORDS)
    if s_hits > 0:
        candidates.append((Intent.SENALES, 0.5 + 0.1 * min(s_hits, 3), {}))

    # 6) Buenas prácticas específicas
    sub = detect_bp_subtopic(text)
    if sub:
        candidates.append((Intent.BP_ESPECIFICAS, 0.65, {"subtema": sub}))

    # 7) Buenas prácticas generales
    bp_hits = count_hits(text, BP_GENERALES_KEYWORDS)
    if bp_hits > 0:
        candidates.append((Intent.BP_GENERALES, 0.5 + 0.1 * min(bp_hits, 3), {}))

    # 8) Saludo / menú
    sal_hits = count_hits(text, SALUDO_KEYWORDS)
    if sal_hits > 0:
        candidates.append((Intent.SALUDO_MENU, 0.46 + 0.05 * min(sal_hits, 2), {}))

    if not candidates:
        return NLUResult(Intent.FUERA, 0.3, {})

    # Ponderación ligera por prioridad
    weighted = []
    for it, sc, sl in candidates:
        weight = 1.0 + (INTENT_PRIORITY.get(it, 1) - 3) * 0.1
        weighted.append((it, sc * weight, sl))

    weighted.sort(key=lambda x: x[1], reverse=True)
    top_intent, top_score, top_slots = weighted[0]
    alt: Optional[Tuple[Intent, float]] = None
    if len(weighted) > 1:
        second_intent, second_score, _ = weighted[1]
        if top_intent != second_intent:
            delta = max(1e-6, top_score) - second_score
            rel_gap = delta / max(top_score, 1e-6)
            if rel_gap < DESAMBIG_MARGIN:
                alt = (second_intent, second_score)

    return NLUResult(top_intent, float(top_score), top_slots, alt)


# ========== Plantillas (NLG) ==========
def tpl_saludo_menu() -> str:
    return (
        "👋 ¡Hola! Puedo ayudarte a <b>aprender</b> sobre phishing por correo:\n"
        "🔎 Señales comunes\n"
        "📘 Definiciones y terminología (SPF/DKIM/DMARC, 2FA, etc.)\n"
        "🛡️ Buenas prácticas (enlaces, 2FA, adjuntos, QR)\n"
        "¿Por dónde empezamos?"
    )


def tpl_despedida() -> str:
    return (
        "👋 ¡Hasta luego! Fue un placer ayudarte.\n"
        "Recuerda siempre:\n"
        "🔗 Verifica los enlaces antes de hacer clic\n"
        "🔐 Usa autenticación de dos factores (2FA/MFA)\n"
        "📞 Ante la duda, contacta directamente con la organización\n"
        "🛡️ ¡Mantente seguro!"
    )


def tpl_senales_comunes() -> str:
    return (
        "<b>Señales típicas de phishing por correo</b>\n"
        "⚠️ Urgencia o amenazas inusuales.\n"
        "🕵️ Remitente o <b>display name</b> que no coincide con el email real.\n"
        "🌐 Enlaces cuyo dominio difiere de la marca esperada.\n"
        "💳 Solicitud de credenciales, pagos o datos sensibles.\n"
        "📎 Adjuntos inesperados o uso de acortadores/QR sin contexto.\n"
        "*Idea práctica:* pasa el cursor por el enlace y verifica el <b>dominio</b> antes de hacer clic.\n"
    )


def tpl_bp_generales() -> str:
    return (
        "<b>Buenas prácticas esenciales (correo)</b>\n"
        "1) Verifica remitente y dominio real antes de interactuar.\n"
        "2) No ingreses credenciales desde enlaces recibidos.\n"
        "3) Usa <b>2FA/MFA</b> en tus cuentas importantes.\n"
        "4) Desconfía de urgencias y premios.\n"
        "5) Reporta sospechas por el canal oficial.\n"
        "¿Profundizamos en <b>enlaces</b>, <b>contraseñas/gestores</b>, <b>2FA</b>, <b>adjuntos</b> o <b>QR</b>?"
    )


def tpl_bp_especificas(subtema: str) -> str:
    if subtema == "enlaces":
        return (
            "<b>Recomendaciones al ver un enlace o link</b>\n"
            "1) Pasa el cursor y compara el dominio con la marca esperada.\n"
            "2) Evita acortadores sin contexto; entra por marcador propio.\n"
            "3) Revisa subdominios engañosos (p. ej., `seguridad.tu-banco.com` ≠ `tu-banco.seguridad.com`).\n"
            "4) Si dudas, <b>no hagas click</b>. Abre el sitio manualmente.\n"
        )
    if subtema == "contrasenas":
        return (
            "<b>Contraseñas y gestores</b>\n"
            "• Usa un <b>gestor</b> para crear y guardar claves únicas.\n"
            "• Activa <b>2FA</b> donde sea posible.\n"
            "• Desconfía de correos que pidan verificar tu contraseña.\n"
            "¿Quieres ver <b>señales comunes</b> o una <b>definición</b> (p. ej., ingeniería social)?"
        )
    if subtema == "2fa":
        return (
            "<b>2FA: ¿Por qué te protege?</b>\n"
            "• Bloquea accesos incluso si adivinan tu contraseña.\n"
            "• Usa app de autenticación sobre SMS cuando puedas.\n"
        )
    if subtema == "adjuntos":
        return (
            "<b>Adjuntos seguros</b>\n"
            "• Desconfía de `.zip`, `.exe`.\n"
            "• Si no esperabas el archivo, confirma por otro canal.\n"
        )
    if subtema == "qr":
        return (
            "<b>Códigos QR con cabeza</b>\n"
            "• Evita escanear QR de correos inesperados.\n"
            "• Si debes, verifica a qué dominio apunta antes de iniciar sesión.\n"
        )
    return tpl_bp_generales()


def tpl_terminologia(termino: str) -> str:
    termino_norm = termino.strip() if termino else "el término"
    return (
        f"<b>{termino_norm} en correo electrónico</b>\n"
        f"{_def_breve_termino(termino_norm)}\n"
        f"<b>Para qué sirve:</b> {_beneficio_termino(termino_norm)}\n"
        f"<b>Limitaciones:</b> {_limitacion_termino(termino_norm)}\n"
    )


def tpl_definicion(termino: str, detalle: str = "estandar") -> str:
    t = termino.strip() if termino else "el término"
    if detalle == "breve":
        return (
            f"<b>¿Qué es {t}?</b> {_def_breve_termino(t)}\n"
            f"¿Quieres una explicación con ejemplos o ver <b>señales</b> relacionadas?"
        )
    if detalle == "detalle":
        return (
            f"<b>{t}: cómo funciona y por qué importa</b>\n"
            f"{_como_funciona_termino(t)}\n"
            f"<b>Señales típicas:</b> {_senales_termino(t)}\n\n"
            f"<b>Limitaciones / notas:</b> {_limitacion_termino(t)}\n\n"
            f"¿Seguimos con un <b>checklist práctico</b> o con <b>señales comunes</b>?"
        )
    return (
        f"<b>{t}: definición clara</b>\n"
        f"{_def_estandar_termino(t)}\n"
        f"¿Prefieres ver <b>señales relacionadas</b> o <b>buenas prácticas</b>?"
    )


def tpl_puente_analisis() -> str:
    return (
        "Para <b>analizar</b> un correo real, te derivo al flujo de análisis con nuestro modelo especializado.\n"
        "Mientras tanto, puedo <b>explicarte</b> señales, definiciones y buenas prácticas.\n"
        "¿Quieres ver <b>señales comunes</b> o una <b>definición</b>?"
    )


def tpl_desambiguacion(o1: Intent, o2: Intent) -> str:
    return (
        f"Puedo ayudarte con <b>{_intent_label(o1)}</b> o <b>{_intent_label(o2)}</b>.\n"
        "¿Cuál prefieres ahora?"
    )


def tpl_fuera_de_ambito() -> str:
    return (
        "Puedo ayudarte a <b>aprender</b> sobre phishing por correo electrónico.\n"
        "¿Quieres ver <b>señales comunes</b> o una definición?"
    )


# ========== Contenido pedagógico ==========
def _intent_label(intent: Intent) -> str:
    mapping = {
        Intent.SENALES: "señales comunes",
        Intent.DEFINICION: "definiciones",
        Intent.BP_GENERALES: "buenas prácticas",
        Intent.BP_ESPECIFICAS: "buenas prácticas específicas",
        Intent.TERMINOLOGIA: "terminología",
    }
    return mapping.get(intent, intent.value)


def _def_breve_termino(termino: str) -> str:
    t = normalize(termino)
    t_clean = t.replace("-", " ")
    if "spf" in t:
        return "SPF es un registro DNS que indica qué servidores pueden enviar correos en nombre de tu dominio."
    if "dkim" in t:
        return "DKIM firma criptográficamente los correos para que el receptor valide que no se alteraron."
    if "dmarc" in t:
        return "DMARC indica cómo tratar correos que fallan SPF/DKIM y permite reportes de suplantación."
    if "2fa" in t or "mfa" in t or "doble factor" in t or "autenticacion" in t:
        return "2FA/MFA añade una verificación adicional (código/app/llave física) además de la contraseña para proteger tu cuenta."
    if "homograf" in t:
        return "Los homógrafos usan caracteres parecidos (p. ej., 'app1e' vs. 'apple') para engañar."
    if "display name" in t:
        return "El 'display name' es el nombre visible del remitente; puede suplantarse aunque el email sea sospechoso."
    if "reply to" in t_clean:
        return "Reply-To indica a qué dirección se enviará tu respuesta, aunque el correo aparente venir de otra cuenta."
    if "return path" in t_clean:
        return "Return-Path es la dirección que recibirá rebotes; si pertenece a otro dominio puede revelar un desvío."
    if "smishing" in t:
        return "Smishing es phishing por SMS: enlaces/trampas enviados por mensajes de texto."
    if "vishing" in t:
        return "Vishing es phishing por voz/llamadas, usando presión o urgencia para que reveles datos."
    if "bec" in t:
        return "Business Email Compromise: suplantación/manejo de hilos para desviar pagos o robar info."
    if "ingenieria" in t:
        return "Ingeniería social: manipulación psicológica para influir en decisiones y obtener información o acción."
    if "phishing" in t:
        return "Intento de obtener datos o dinero mediante engaño por correo haciéndose pasar por otro."
    return "Concepto de seguridad en correo; puedo darte ejemplos y señales típicas."


def _def_estandar_termino(termino: str) -> str:
    t = normalize(termino)
    if "2fa" in t or "mfa" in t or "doble factor" in t or "autenticacion" in t:
        return (
            "Segundo factor de autenticación además de la contraseña (app autenticadora, token, llave física o SMS) que reduce drásticamente el impacto de contraseñas filtradas o robadas.")
    if "phishing" in t:
        return (
            "Técnica por la que un atacante se hace pasar por una entidad legítima para que entregues credenciales, "
            "descargues malware o realices pagos, usualmente mediante correos con enlaces o adjuntos.")
    if "smishing" in t:
        return ("Variante de phishing vía SMS que incluye enlaces a sitios falsos o números para devolver la llamada, "
                "aprovechando urgencia o premios falsos.")
    if "vishing" in t:
        return (
            "Variante por llamada telefónica o mensajes de voz; el atacante finge ser soporte/banco para obtener datos o transferencias.")
    if "bec" in t:
        return (
            "Fraude de correo empresarial donde se comprometen cuentas o se imitan dominios para instruir pagos o cambios bancarios.")
    if "ingenieria" in t:
        return (
            "Conjunto de tácticas que explotan sesgos/urgencia/confianza para inducir a acciones riesgosas o revelar información sensible.")
    return _def_breve_termino(termino)


def _ejemplo_breve_termino(termino: str) -> str:
    t = normalize(termino)
    if "phishing" in t:
        return "Correo de 'Soporte' que pide 'verificar tu contraseña' en un enlace no oficial."
    if "2fa" in t or "mfa" in t or "autenticacion" in t:
        return "Inicio de sesión que, además de clave, pide un código de una app autenticadora."
    if "smishing" in t:
        return "SMS: "
        Paquete
        retenido, paga
        tarifas
        aquí: bit.ly / ...
        "."
    if "vishing" in t:
        return "Llamada 'del banco' pidiendo códigos de un solo uso para 'verificar identidad'."
    if "bec" in t:
        return "Correo 'del CFO' solicitando cambio urgente de cuenta bancaria para un pago."
    if "ingenieria" in t:
        return "Correo urgente de 'IT' solicitando cambiar contraseña por enlace sospechoso."
    return "Mensaje que pide acción urgente y enlaza a un dominio que no coincide con la marca."


def _como_funciona_termino(termino: str) -> str:
    t = normalize(termino)
    if "dmarc" in t:
        return ("DMARC se apoya en SPF y DKIM; define políticas (none/quarantine/reject) y reportes para "
                "ayudar a controlar la suplantación de dominio.")
    if "2fa" in t or "mfa" in t or "autenticacion" in t:
        return ("Añade un factor 'algo que tienes' (app, token) o 'algo que eres' a 'algo que sabes' (contraseña), "
                "bloqueando accesos aunque la clave se filtre.")
    return _def_estandar_termino(termino)


def _senales_termino(termino: str) -> str:
    t = normalize(termino)
    if "homograf" in t:
        return "dominios parecidos (app1e), enlaces con letras sustituidas, subdominios engañosos."
    if "ingenieria" in t:
        return "urgencia excesiva, solicitudes inusuales, apelar a autoridad o miedo."
    return "urgencia, enlaces no coincidentes, remitente dudoso, petición de datos."


def _beneficio_termino(termino: str) -> str:
    t = normalize(termino)
    t_clean = t.replace("-", " ")
    if "spf" in t:
        return "Ayuda a los receptores a rechazar orígenes no autorizados."
    if "dkim" in t:
        return "Aporta integridad y autenticidad al contenido del correo."
    if "dmarc" in t:
        return "Permite políticas anti-suplantación y visibilidad mediante reportes."
    if "2fa" in t or "mfa" in t or "autenticacion" in t:
        return "Reduce drásticamente el riesgo aunque la contraseña se filtre."
    if "reply to" in t_clean:
        return "Permite dirigir respuestas a una bandeja controlada (soporte, ticketing) sin exponer la cuenta principal."
    if "return path" in t_clean:
        return "Facilita gestionar rebotes y verificar qué dominio controla realmente el envío."
    return "Mejora la comprensión y la detección de señales de phishing."


def _limitacion_termino(termino: str) -> str:
    t = normalize(termino)
    t_clean = t.replace("-", " ")
    if "spf" in t:
        return "No protege bien el reenvío; puede fallar con forwarders si no se ajusta."
    if "dkim" in t:
        return "Firmas mal configuradas pueden fallar; no evita suplantación por sí sola."
    if "dmarc" in t:
        return "Requiere SPF/DKIM y alineación correctos; no cubre todos los casos."
    if "2fa" in t or "mfa" in t or "autenticacion" in t:
        return "El phishing puede intentar robar códigos; evita introducirlos en sitios no verificados."
    if "reply to" in t_clean:
        return "Puede apuntar a un actor distinto al remitente real; siempre verifica el dominio antes de responder."
    if "return path" in t_clean:
        return "Los atacantes pueden definir un Return-Path propio aunque el From parezca legítimo."
    return "Ningún control es perfecto; combina medidas técnicas y educación."


# ========== FSM mínima ==========
@dataclass
class DialogueContext:
    state: State = State.INICIO
    ultimo_tema: Optional[str] = None
    preferencia_formato: str = "estandar"


def next_response(user_text: str, ctx: DialogueContext) -> Tuple[str, DialogueContext]:
    nlu = nlu_detect(user_text)

    if nlu.intent == Intent.DESPEDIDA:
        return tpl_despedida(), DialogueContext(state=State.FINALIZADO)

    if nlu.intent == Intent.ANALISIS_PETICION:
        return tpl_puente_analisis(), ctx

    if nlu.alt and nlu.intent not in (Intent.SALUDO_MENU,):
        return tpl_desambiguacion(nlu.intent, nlu.alt[0]), DialogueContext(state=State.DESAMBIG)

    if nlu.intent == Intent.SALUDO_MENU:
        return tpl_saludo_menu(), DialogueContext(state=State.MENU_EDU)

    if nlu.intent == Intent.SENALES:
        return tpl_senales_comunes(), DialogueContext(state=State.MENU_EDU, ultimo_tema="senales")

    if nlu.intent == Intent.BP_GENERALES:
        return tpl_bp_generales(), DialogueContext(state=State.CHECKLIST, ultimo_tema="bp_generales")

    if nlu.intent == Intent.BP_ESPECIFICAS:
        sub = nlu.slots.get("subtema", "enlaces")
        return tpl_bp_especificas(sub), DialogueContext(state=State.CHECKLIST, ultimo_tema=f"bp_{sub}")

    if nlu.intent == Intent.TERMINOLOGIA:
        term = _guess_term_from_text(user_text)
        return tpl_terminologia(term), DialogueContext(state=State.EXPLICACION, ultimo_tema=term)

    if nlu.intent == Intent.DEFINICION:
        term = nlu.slots.get("term") or nlu.slots.get("term2") or _guess_term_from_text(user_text)
        return tpl_definicion(term, "estandar"), DialogueContext(state=State.EXPLICACION, ultimo_tema=term)

    return tpl_fuera_de_ambito(), DialogueContext(state=State.MENU_EDU)


def _guess_term_from_text(text: str) -> str:
    t = normalize(text)
    for term in (TERMINOLOGIA_TERMS + CONCEPT_KEYWORDS):
        if term in t:
            return term
    tokens = [w for w in re.findall(r"[a-z0-9\-\._]+", t) if len(w) > 2]
    return tokens[-1] if tokens else "phishing"


# ========== Demo CLI ==========
if __name__ == "__main__":
    print("ChatBot educativo (reglas) — escribe 'salir' para terminar.\n")
    ctx = DialogueContext()
    while True:
        try:
            user = input("Tú: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nHasta luego.")
            break
        if not user or user.lower() in {"salir", "exit", "quit"}:
            print("Bot: ¡Hasta luego!")
            break
        reply, ctx = next_response(user, ctx)
        print(f"Bot: {reply}\n")
        if ctx.state == State.FINALIZADO:
            break
