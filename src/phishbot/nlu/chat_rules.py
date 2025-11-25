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
    "hola", "buenas", "que puedes hacer", "ayuda", "menu", "opciones",
    "empezar", "inicio", "buenos dias", "buenas tardes", "buenas noches",
    "hi", "hello"
]

DESPEDIDA_KEYWORDS = [
    "adios", "chao", "chau", "bye", "salir", "exit", "quit",
    "hasta luego", "nos vemos", "hasta pronto", "me voy",
    "gracias adios", "cerrar", "terminar"
]

CONTINUE_KEYWORDS = [
    "mas informacion", "mas detalles", "sigue", "continuar",
    "explica mas", "no entendi", "otro ejemplo", "dame mas",
    "ver mas", "profundizar"
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

    # 1.5) Petición explícita de lista de definiciones
    if "definicion" in text or "definiciones" in text or "conceptos" in text:
        # Si es solo la palabra o una frase corta pidiendo verlas
        if len(text.split()) < 4:
             candidates.append((Intent.DEFINICION, 0.9, {}))

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
        "👋 <b>¡Hola! Soy tu asistente de seguridad.</b><br>"
        "Puedo ayudarte a detectar y prevenir el phishing. ¿Qué te gustaría hacer?\n\n"
        "🔎 <b>Ver señales comunes</b> de estafas\n"
        "📘 <b>Consultar definiciones</b> (Phishing, DKIM, 2FA, Homógrafos, etc.)\n"
        "🛡️ <b>Aprender buenas prácticas</b> para protegerte\n"
        "📧 <b>Analizar un correo</b> sospechoso\n\n"
        "<i>Escribe tu duda o elige una opción.</i>"
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
        f"{_def_breve_termino(termino_norm)}"
    )


def tpl_definicion(termino: str, detalle: str = "estandar") -> str:
    # Si no hay término específico, mostrar lista
    if not termino or termino == "phishing":
        # "phishing" por defecto si falla la detección, pero si el usuario solo dijo "definicion"
        # queremos mostrar la lista. Ajustaremos la lógica de llamada.
        pass

    t = termino.strip() if termino else ""
    
    # Si no hay término o el término es la propia palabra "definición", mostrar lista
    if not t or t in ["definicion", "definiciones", "conceptos", "terminos"]:
        return _get_all_definitions()

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
        "<b>Analizar correo sospechoso</b><br>"
        "Sube el archivo <b>.eml</b> para que nuestro modelo híbrido lo revise.<br><br>"
        "<button class='chat-upload-btn' style='background-color:#10b981;color:white;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;'>📂 Subir archivo .eml</button>"
    )


def tpl_desambiguacion(o1: Intent, o2: Intent) -> str:
    return (
        f"Puedo ayudarte con <b>{_intent_label(o1)}</b> o <b>{_intent_label(o2)}</b>.\n"
        "¿Cuál prefieres ahora?"
    )


def tpl_fuera_de_ambito() -> str:
    return (
        "🤔 No estoy seguro de haber entendido eso.<br>"
        "Puedo explicarte sobre <b>phishing</b>, <b>seguridad en correos</b> o <b>analizar mensajes</b>.\n\n"
        "Prueba con:\n"
        "• \"¿Qué es el phishing?\"\n"
        "• \"Señales de alerta\"\n"
        "• \"Buenas prácticas\"\n"
        "• \"Analizar correo\""
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
        return (
            "SPF es un mecanismo que permite a un dominio indicar qué servidores están autorizados para enviar correos en su nombre.\n\n"
            "<b>Para qué sirve:</b>\n"
            "Ayuda a detectar si un mensaje fue enviado desde un servidor legítimo o desde uno no autorizado, lo que permite identificar intentos de suplantación o phishing.\n\n"
            "<b>Recomendación:</b>\n"
            "Si un correo falla SPF o proviene de un servidor no autorizado, trátalo como sospechoso; es una señal común en correos falsificados."
        )
    if "dkim" in t:
        return (
            "DKIM es un método que permite a un servidor de correo firmar digitalmente los mensajes para demostrar que realmente fueron enviados por ese dominio y que no fueron alterados durante el envío\n\n"
            "<b>Ejemplo: </b>"
            "Un correo de empresa.com lleva una firma DKIM que el sistema del destinatario verifica como auténtica. Si al firmar no coincide , el mensaje podría haber sido manipulado o falsificado.\n\n"
            "<b>Recomendación:</b> Antes de confiar en un correo, valida la verificación DKIM; los mensajes sin DKIM o con fallos en la firma pueden ser señales de phishing."
        )
    if "dmarc" in t:
        return (
            "DMARC es una política que los dominios usan para indicar cómo deben manejarse los correos que no pasan las validaciones de autenticación como SPF o DKIM, ayudando a prevenir suplantaciones.\n\n"
            "<b>Ejemplo: </b>"
            "Si empresa.com configura DMARC con una política de 'reject', cualquier correo que no pase las validaciones SPF o DKIM será rechazado.\n\n"
            "<b>Recomendación:</b> Confía más en correos de dominios que tienen DMARC correctamente configurado; si un mensaje falla DMARC; trátalo como sospechoso de phishing."
        )
    if "2fa" in t or "mfa" in t or "doble factor" in t or "autenticacion" in t:
        return "2FA/MFA añade una verificación adicional (código/app/llave física) además de la contraseña para proteger tu cuenta."
    if "homograf" in t:
        return (
            "Un ataque homógrafo consiste en crear direcciones o enlaces que parecen idénticos a los legítimos usando caracteres visualmente similares, como letras de otro alfabeto. Esto para engañar al usuario y llevarlo a sitios falsos.\n\n"
            "<b>Ejemplo: </b>"
            "El dominio 'apple.com' puede ser imitado como 'аррle.com' aquí a simple vista lucen iguales, pero en la segunda se usaron algunas letras que provienen del alfabeto cirílico.\n\n"
            "<b>Recomendación:</b> Antes de hacer clic o ingresar datos, revisa cuidadosamente la dirección del enlace; si es posible, escribelo manualmente el sitio o utiliza marcadores oficiales para evitar caer en imitaciones."
        )
    if "display name" in t:
        return ("El <b>display name</b> es el nombre que aparece como remitente cuando recibes un correo, antes de ver la dirección completa."
        "Sirve para que el destinatario pueda identificar quién envía el mensaje más fácil.\n\n"
        "<b>Ejemplo: </b> \n"
        "Si el display name es 'María López - Ventas' y la dirección es mlopez@empresa.com, el destinatario verá:\n"
        "De: María López - Ventas mlopez@empresa.com\n\n"
        "<b>Recomendación:</b> No confíes solo en el nombre que aparece como remitente; revisa siempre la dirección de correo completa."
        )
    if "reply to" in t_clean:
        return ( "Reply-To es la dirección de correo a la que se enviarán las respuestas, aunque el mensaje original haya sido enviado desde otra dirección.\n"
        "Sirve para dirigir las respuestas a una cuenta distinta, por gestión o conveniencia.\n\n"
        "<b>Ejemplo: </b> \n"
        "Un correo llega desde notificaciones@servicio.com, pero el reply-to es soporte@servicio.com.\n"
        "Si respondes, tu mensaje irá a soporte@servicio.com, no a notificaciones@servicio.com.\n\n"
        "<b>Recomendación:</b> Antes de responder, revisa si el reply-to coincide con la dirección legítima; los atacantes suelen usar direcciones diferentes para desviar respuestas."
        )
    if "return path" in t_clean:
        return ("Return-Path es la dirección a la que se devuelven los correos que no pudieron entregarse (por ejemplo "
        "cuando la dirección del destinatario no existe). Sirve para gestionar los 'rebotes' y saber qué mensajes fallaron."
        "<b>Ejemplo: </b> \n"
        "Un correo se envía desde boletines@empresa.com, pero el return-path es rebotes@empresa.com.\n"
        "Si el mensaje no llega, el aviso de error se enviará a rebotes@empresa.com.\n\n"
        "<b>Recomendación:</b> Si notas discrepancias entre el remitente y el return-path, considera el mensaje sospechoso; es una señal frecuente en correos falsificados"
        )
    if "smishing" in t:
        return (
            "El smishing es una variante del phishing en el que los atacantes envían mensajes de texto (SMS) para engañarte y hacer que entregues datos personales, claves o dinero.\n\n"
            "<b>Ejemplo: </b> \n"
            '"Tu banco ha bloqueado tu tarjeta. Verifica tu identidad en este enlace: http://seguridad-banco-123.com”\n\n'
            "<b>Recomendación:</b> No abras enlaces ni compartas datos desde SMS inesperados; verifica siempre directamente con la entidad u organización usando canales o medios oficiales."
        )
    if "vishing" in t:
        return (
            "El vishing es una variante del phishing en el que los atacantes usan llamadas telefónicas para hacerse pasar por una entidad confiable y obtener información personal, claves o pagos.\n\n"
            "<b>Ejemplo: </b> \n"
            '"Le llamamos del departamento de seguridad de su banco. Necesitamos que nos confirme el código que acaba de recibir para evitar un bloqueo"\n\n'
            "<b>Recomendación:</b> No compartas información sensible por teléfono; si sospechas, cuelga y contacta tú mismo a la entidad usando números oficiales."
        )
    if "bec" in t:
        return "Business Email Compromise: suplantación/manejo de hilos para desviar pagos o robar info."
    if "ingenieria" in t:
        return "Ingeniería social: manipulación psicológica para influir en decisiones y obtener información o acción."
    if "phishing" in t:
        return "Intento de obtener datos o dinero mediante engaño por correo haciéndose pasar por otro."
    return (
        "Los encabezados de un correo son la información técnica que muestra de dónde salió realmente un mensaje, por dónde pasó y cómo fue autenticado."
    )


def _def_estandar_termino(termino: str) -> str:
    t = normalize(termino)
    if "2fa" in t or "mfa" in t or "doble factor" in t or "autenticacion" in t:
        return (
            "La autenticación en dos pasos (2FA) es un método de seguridad que requiere dos formas diferentes de identificación para acceder a una cuenta. "
            "Normalmente requiere una contraseña y un código de verificación que recibes en tu teléfono o en una app. "
            "Esto hace mucho más difícil que alguien entre a tus cuentas sin permiso.\n\n"
            "<b>Recomendación:</b> Activa 2FA en todas tus cuentas, especialmente en cuentas bancarias y de correo."
        )
    if "phishing" in t:
        return (
            "El <b>phishing</b> es un tipo de engaño en el que un atacante se hace pasar por una entidad confiable para que la víctima entregue información personal, "
            "contraseñas o datos financieros, normalmente a través de correos electrónicos, mensajes o sitios falsos.\n\n"
            "<b>Ejemplo: </b> \n"
            '"Actualiza tu cuenta bancaria haciendo clic aquí: http://seguridad-banco-123.com”\n\n'
            "<b>Recomendación:</b> No hagas clic en enlaces inesperados ni entregues datos sensibles; verifica siempre la dirección del sitio y contacta a la entidad por canales oficiales antes de actuar."
        )
    if "smishing" in t:
        return (
            "El smishing es una variante del phishing en el que los atacantes envían mensajes de texto (SMS) para engañarte y hacer que entregues datos personales, claves o dinero.\n\n"
            "<b>Ejemplo: </b> \n"
            '"Tu banco ha bloqueado tu tarjeta. Verifica tu identidad en este enlace: http://seguridad-banco-123.com”\n\n'
            "<b>Recomendación:</b> No abras enlaces ni compartas datos desde SMS inesperados; verifica siempre directamente con la entidad u organización usando canales o medios oficiales."
        )
    if "vishing" in t:
        return (
            "El vishing es una variante del phishing en el que los atacantes usan llamadas telefónicas para hacerse pasar por una entidad confiable y obtener información personal, claves o pagos.\n\n"
            "<b>Ejemplo: </b> \n"
            '"Le llamamos del departamento de seguridad de su banco. Necesitamos que nos confirme el código que acaba de recibir para evitar un bloqueo"\n\n'
            "<b>Recomendación:</b> No compartas información sensible por teléfono, si sospechas cuelga y contacta tú mismo a la entidad usando números oficiales."
        )   
    if "bec" in t:
        return (
            "BEC (Business Email Comromise) es un tipo de phishing empresarial que se hace pasar por una persona de confianza.\n"
            "<b>Ejemplo: </b>"
            "Un jefe o un proveedor que pide cambios urgentes en una cuenta bancaria.\n"
            "Consiste en engañar a la víctima y lograr que envíe dinero o información sensible. Es una estafa basada en la suplantación y el engaño, no en romper sistemas técnicos.\n\n"
            "<b>Recomendación:</b> Desconfía de solicitudes de pagos o cambios urgentes hechas por correo; verifica siempre por otro canal o antes de actuar."
            )
    if "ingenieria" in t:
        return (
            "La ingenería social es una técnica de manipulación en la que un atacante aprovecha la confianza o el descuido de una persona para obtener información sensible, acceso o hacer que realice una acción perjudicial.\n\n"
            "<b>Ejemplo: </b>"
            "Alguien se hace pasar por soporte técnico y pide tu contraseña 'para arreglar un problema urgente'.\n\n"
            "<b>Recomendación:</b> Verifica siempre la identidad de quien solicita información o acceso; no compartas datos sensibles sin confirmar por canales o medios oficiales."
        )
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
        # Si no hay slots, intentamos adivinar. Si no hay nada claro, pasamos None para mostrar lista.
        term = nlu.slots.get("term") or nlu.slots.get("term2")
        if not term:
            # Si el usuario dijo "definicion" a secas, term es None -> lista
            # Si dijo "que es phishing", term es "phishing"
            guessed = _guess_term_from_text(user_text)
            # Hack: si _guess devuelve "phishing" (default) pero el usuario NO escribió phishing,
            # asumimos que quiere la lista general.
            if "phishing" not in normalize(user_text) and guessed == "phishing":
                term = None
            else:
                term = guessed

        return tpl_definicion(term, "estandar"), DialogueContext(state=State.EXPLICACION, ultimo_tema=term)

    # Manejo de continuación / contexto simple
    if count_hits(normalize(user_text), CONTINUE_KEYWORDS) > 0 and ctx.ultimo_tema:
        # Si pide más info y tenemos un tema previo
        if ctx.ultimo_tema.startswith("bp_"):
            return tpl_bp_generales(), ctx
        return tpl_definicion(ctx.ultimo_tema, "detalle"), ctx

    return tpl_fuera_de_ambito(), DialogueContext(state=State.MENU_EDU)


def _guess_term_from_text(text: str) -> str:
    t = normalize(text)
    for term in (TERMINOLOGIA_TERMS + CONCEPT_KEYWORDS):
        if term in t:
            return term
    tokens = [w for w in re.findall(r"[a-z0-9\-\._]+", t) if len(w) > 2]
    return tokens[-1] if tokens else "phishing"


def _get_all_definitions() -> str:
    # Lista curada de conceptos para mostrar al usuario (sin duplicados/sinónimos)
    # Formato: "Término a mostrar" (que el usuario puede escribir)
    display_terms = [
        "Phishing",
        "Smishing",
        "Vishing",
        "Ingeniería Social",
        "BEC (Business Email Compromise)",
        "2FA / MFA",
        "SPF",
        "DKIM",
        "DMARC",
        "Return-Path",
        "Reply-To",
        "Display Name",
        "Homógrafos",
        "Cabeceras"
    ]
    
    html = "<b>📚 Definiciones y conceptos útiles:</b><br><ul>"
    for t in sorted(display_terms):
        # Usamos el primer término para el ejemplo de comando si es compuesto
        cmd_term = t.split("/")[0].split("(")[0].strip().lower()
        html += f"<li>{t}</li>"
    html += "</ul><br><i>Escribe 'que es [término]' para ver detalles.</i>"
    return html


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
