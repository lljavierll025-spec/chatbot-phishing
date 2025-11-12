# -*- coding: utf-8 -*-
# Uso:
#   python eml_feature_extractor.py /ruta/al/correo.eml
# Salida:
#   - Imprime un JSON con "headers", "content", "attachments" y "features"
#
# NOTAS DE SEGURIDAD:
# - No “abrimos” adjuntos, solo los enumeramos y calculamos hash de su payload.
# - No seguimos enlaces ni hacemos peticiones externas.
# - El análisis se hace localmente y de forma determinista.

import sys
import re
import json
import hashlib
import base64
import unicodedata
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from html.parser import HTMLParser
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse


# ----------------------------
# Utilidades
# ----------------------------

URL_REGEX = re.compile(
    r'''(?ix)
    \b(                             # inicio de la URL
      (?:https?://|ftp://)          # esquema
      [^\s<>"'()]{2,}               # resto
    )
    '''
)

# Palabras de urgencia / ingeniería social (ajusta a tu dominio/lenguaje)
URGENCY_WORDS = [
    "urgente", "urgencia", "inmediato", "inmediatamente", "suspension", "suspensión",
    "expira", "expirara", "vence", "hoy", "verifica", "verificar", "actualiza",
    "actualizar", "bloqueado", "bloqueada", "alerta", "alert", "seguridad", "pago",
    "factura", "ganaste", "ganador", "premio"
]

URGENCY_EMPHASIS = [
    "verifica tu cuenta", "actualiza tu cuenta", "actualiza tus datos",
    "confirma tu identidad", "accion requerida", "action required",
    "important update required", "evita la suspension",
    "evita la suspensión", "riesgo de bloqueo", "suspenderemos tu cuenta"
]

SUSPICIOUS_EXTS = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".ps1",
                   ".docm", ".xlsm", ".pptm", ".hta", ".iso", ".img", ".lnk", ".msi", ".apk", ".zip", ".rar"}


def normalize(s: str) -> str:
    return (s or "").strip()


def domain_of_email(addr: str) -> Optional[str]:
    """
    Extrae dominio de una dirección 'Display Name <user@domain>' o 'user@domain'
    """
    if not addr:
        return None
    m = re.search(r"<([^>]+)>", addr)
    email_addr = m.group(1) if m else addr
    email_addr = email_addr.strip().strip('"').strip("'")
    m2 = re.search(r"@([A-Za-z0-9\.\-\_]+)$", email_addr)
    return m2.group(1).lower() if m2 else None


def domain_of_url(u: str) -> Optional[str]:
    try:
        p = urlparse(u)
        host = p.hostname
        if host:
            return host.lower()
    except Exception:
        pass
    return None


MULTI_LEVEL_TLDS = {
    "co.uk", "com.au", "com.br", "com.ar", "com.mx", "com.tr", "com.cn",
    "com.sa", "com.eg", "com.ve", "com.co", "com.pe", "com.cl"
}

DOMAIN_ALIASES = {
    "c.gle": "google.com",
    "g.co": "google.com",
    "googlemail.com": "google.com",
    "gmail.com": "google.com",
    "youtube.com": "google.com",
    "yt.be": "google.com",
    "1e100.net": "google.com",
    "facebookmail.com": "facebook.com",
    "fb.com": "facebook.com",
    "messaging.microsoft.com": "microsoft.com",
    "outlook.com": "microsoft.com",
    "office365.com": "microsoft.com"
}

TRUSTED_DOMAIN_GROUPS = [
    {"google.com", "gmail.com", "googlemail.com", "g.co", "c.gle", "youtube.com", "yt.be", "android.com", "withgoogle.com", "googleapis.com", "1e100.net"},
    {"facebook.com", "facebookmail.com", "fb.com", "meta.com", "instagram.com", "whatsapp.com"},
    {"microsoft.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com", "live.com"},
    {"apple.com", "icloud.com", "me.com"},
]


def _registrable_domain(domain: str) -> str:
    domain = (domain or "").lower().strip(".")
    if not domain:
        return ""
    if domain in DOMAIN_ALIASES:
        return DOMAIN_ALIASES[domain]
    labels = domain.split(".")
    if len(labels) < 2:
        return domain
    suffix = ".".join(labels[-2:])
    for multi in MULTI_LEVEL_TLDS:
        if domain.endswith("." + multi):
            parts_needed = len(multi.split(".")) + 1
            if len(labels) >= parts_needed:
                return ".".join(labels[-parts_needed:])
    return suffix


def _in_trusted_group(a: str, b: str) -> bool:
    if not a or not b:
        return False
    for group in TRUSTED_DOMAIN_GROUPS:
        if a in group and b in group:
            return True
    return False


def domains_related(a: Optional[str], b: Optional[str]) -> bool:
    if not a or not b:
        return False
    a = a.lower()
    b = b.lower()
    if a == b:
        return True
    if a.endswith("." + b) or b.endswith("." + a):
        return True
    canon_a = _registrable_domain(a)
    canon_b = _registrable_domain(b)
    if canon_a and canon_a == canon_b:
        return True
    if _in_trusted_group(canon_a or a, canon_b or b):
        return True
    return False


def ext_of_filename(fn: str) -> str:
    fn = (fn or "").lower()
    m = re.search(r"(\.[a-z0-9]{1,6})$", fn)
    return m.group(1) if m else ""

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# ----------------------------
# HTML link extractor
# ----------------------------

class SimpleHTMLLinkExtractor(HTMLParser):
    """Extrae hrefs y también el texto visible de cada <a>."""
    def __init__(self):
        super().__init__()
        self.links: List[Dict[str, str]] = []
        self._current_href: Optional[str] = None
        self._buffer_text: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = None
            for k, v in attrs:
                if k.lower() == "href":
                    href = v
                    break
            self._current_href = href
            self._buffer_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._buffer_text.append(data.strip())

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current_href is not None:
            text = " ".join([t for t in self._buffer_text if t])
            self.links.append({"href": self._current_href, "text": text})
            self._current_href = None
            self._buffer_text = []


# ----------------------------
# Extracción de partes MIME
# ----------------------------

def decode_part(part) -> bytes:
    """
    Devuelve el payload de una parte MIME en bytes (decodificado).
    """
    try:
        payload = part.get_payload(decode=True)
        return payload if isinstance(payload, (bytes, bytearray)) else b""
    except Exception:
        return b""


def text_of_part(part) -> str:
    """
    Devuelve texto decodificado (respetando charset) si es text/*.
    """
    try:
        b = decode_part(part)
        charset = part.get_content_charset() or "utf-8"
        return b.decode(charset, errors="replace")
    except Exception:
        return ""


# ----------------------------
# Parseo de .eml y extracción
# ----------------------------

def parse_eml(path: str) -> EmailMessage:
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def extract_headers(msg: EmailMessage) -> Dict[str, Any]:
    hdr = {}
    for k in msg.keys():
        hdr[k] = normalize(msg.get(k))
    return hdr


def parse_authentication_results(h: str) -> Dict[str, Optional[str]]:
    """
    Extracción muy sencilla de resultados SPF/DKIM/DMARC desde Authentication-Results.
    """
    h = h or ""
    res = {"spf": None, "dkim": None, "dmarc": None}
    # Ej: "Authentication-Results: mx.google.com; spf=pass ...; dkim=pass ...; dmarc=fail ..."
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}\s*=\s*([a-zA-Z]+)", h)
        if m:
            res[mech] = m.group(1).lower()
    return res


def extract_received_chain(headers: Dict[str, str]) -> List[str]:
    """
    Extrae todas las cabeceras Received en orden de aparición (arriba->abajo).
    """
    received = []
    # policy.default agrupa repeticiones con msg.get_all
    # aquí tenemos headers como dict plano; para conservar orden podemos reparsear crudos
    # pero como plantilla, intentamos por claves variantes:
    for k, v in headers.items():
        if k.lower() == "received":
            received.append(v)
    return received


def first_origin_ip_from_received(received_list: List[str]) -> Optional[str]:
    """
    Heurística: toma la última línea Received (la más 'abajo') y extrae una IP.
    """
    if not received_list:
        return None
    last = received_list[-1]
    m = re.search(r"\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]", last)
    if m:
        return m.group(1)
    # IPv6 (simplificado)
    m6 = re.search(r"\[([0-9a-fA-F:]+)\]", last)
    return m6.group(1) if m6 else None


def extract_bodies_and_urls(msg: EmailMessage) -> Dict[str, Any]:
    text_plain_parts: List[str] = []
    text_html_parts: List[str] = []
    attachments: List[Dict[str, Any]] = []
    urls_in_text: List[str] = []
    links_in_html: List[Dict[str, str]] = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = (part.get_content_disposition() or "").lower()
            if disp == "attachment":
                name = part.get_filename() or "unnamed"
                payload = decode_part(part)
                attachments.append({
                    "filename": name,
                    "mime": ctype,
                    "size": len(payload),
                    "sha256": sha256_bytes(payload),
                    "ext": ext_of_filename(name)
                })
            elif ctype == "text/plain":
                text_plain_parts.append(text_of_part(part))
            elif ctype == "text/html":
                text_html_parts.append(text_of_part(part))
    else:
        # Parte única
        ctype = msg.get_content_type()
        if ctype == "text/plain":
            text_plain_parts.append(text_of_part(msg))
        elif ctype == "text/html":
            text_html_parts.append(text_of_part(msg))

    # URLs desde texto plano
    for tp in text_plain_parts:
        for m in URL_REGEX.finditer(tp):
            urls_in_text.append(m.group(1))

    # Enlaces desde HTML
    for html in text_html_parts:
        parser = SimpleHTMLLinkExtractor()
        try:
            parser.feed(html)
            links_in_html.extend(parser.links)
        except Exception:
            pass
        # URLs 'crudas' incrustadas en el HTML (además de <a href>)
        for m in URL_REGEX.finditer(html):
            url = m.group(1)
            # Evita duplicar si ya está en hrefs (heurística simple)
            if not any(d["href"] == url for d in links_in_html):
                links_in_html.append({"href": url, "text": ""})

    return {
        "text_plain": "\n\n".join([t for t in text_plain_parts if t.strip()]),
        "text_html": "\n\n".join([h for h in text_html_parts if h.strip()]),
        "urls_in_text": sorted(set(urls_in_text)),
        "links_in_html": links_in_html,
        "attachments": attachments
    }


# ----------------------------
# Features (lo útil para tu modelo)
# ----------------------------

def _normalize_for_match(text: str) -> str:
    text = (text or "").lower()
    text = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Mn")


def urgency_score(subject: str, body_text: str) -> int:
    """
    Puntaje heurístico: se cuentan términos únicos y señales de énfasis.
    """
    raw = f"{subject or ''}\n{body_text or ''}"
    corpus = _normalize_for_match(raw)

    hits = set()
    for word in URGENCY_WORDS:
        pattern = rf"\b{re.escape(word)}\b"
        if re.search(pattern, corpus):
            base = re.sub(r"(ar|er|ir|s|es)$", "", word)
            hits.add(base or word)

    score = len(hits)
    if any(phrase in corpus for phrase in URGENCY_EMPHASIS):
        score += 1

    if raw.count("!") >= 3:
        score += 1

    if re.search(r"\b[A-ZÁÉÍÓÚ]{4,}\b", subject or ""):
        score += 1

    return min(score, 5)


def link_domain_mismatch(links: List[Dict[str, str]], from_domain: Optional[str]) -> bool:
    """
    True si encontramos algún link cuyo dominio no coincide con el dominio del remitente (cuando debería).
    Nota: esto es heurístico. En muchos correos legítimos, los enlaces apuntan a dominios de tracking de terceros.
    """
    if not from_domain:
        return False
    for link in links:
        d = domain_of_url(link.get("href", ""))
        if d and d != from_domain:
            return True
    return False


def visible_vs_href_mismatch(links: List[Dict[str, str]]) -> bool:
    """
    True si el texto visible del enlace parece una URL/dominio que NO coincide con el href real.
    """
    for link in links:
        text = (link.get("text") or "").strip()
        href = link.get("href") or ""
        if not text or not href:
            continue
        # ¿El texto parece URL?
        if re.search(r"https?://", text) or re.search(r"\b[a-z0-9\-]+\.[a-z]{2,}\b", text, re.I):
            d_text = domain_of_url(text) or guess_domain(text)
            d_href = domain_of_url(href)
            if d_text and d_href and d_text != d_href:
                return True
    return False


def guess_domain(s: str) -> Optional[str]:
    """
    Si 's' no es una URL válida, intenta extraer un dominio 'a mano' del texto.
    """
    m = re.search(r"\b([a-z0-9\-\.]+\.[a-z]{2,})\b", s, re.I)
    return m.group(1).lower() if m else None


def attachment_suspicion_score(att_list: List[Dict[str, Any]]) -> int:
    """
    +2 por cada extensión marcadamente peligrosa, +1 por cada comprimido o macro. Máx 6.
    """
    score = 0
    for a in att_list:
        ext = (a.get("ext") or "").lower()
        if ext in {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".ps1", ".hta", ".lnk", ".msi", ".apk"}:
            score += 2
        elif ext in {".docm", ".xlsm", ".pptm"}:
            score += 2
        elif ext in {".zip", ".rar", ".iso", ".img"}:
            score += 1
    return min(score, 6)


def build_features(headers: Dict[str, str], content: Dict[str, Any]) -> Dict[str, Any]:
    from_h = headers.get("From")
    reply_to_h = headers.get("Reply-To")
    return_path_h = headers.get("Return-Path")
    subject_h = headers.get("Subject")
    msgid_h = headers.get("Message-ID")
    authres_h = headers.get("Authentication-Results")

    from_domain = domain_of_email(from_h or "")
    reply_to_domain = domain_of_email(reply_to_h or "")
    return_path_domain = domain_of_email(return_path_h or "")
    msgid_domain = domain_of_email(msgid_h or "")  # algunos Message-ID incluyen @dominio

    auth = parse_authentication_results(authres_h or "")
    spf = auth["spf"]
    dkim = auth["dkim"]
    dmarc = auth["dmarc"]

    received_list = []
    # Conserva todas las cabeceras "Received" (algunas librerías colapsan en uno)
    for k, v in headers.items():
        if k.lower() == "received":
            received_list.append(v)
    origin_ip = first_origin_ip_from_received(received_list)

    # URLs y dominios
    link_domains = sorted({domain_of_url(d.get("href", "")) for d in content["links_in_html"] if domain_of_url(d.get("href", ""))})
    plain_domains = sorted({domain_of_url(u) for u in content["urls_in_text"] if domain_of_url(u)})
    all_domains = sorted(set([d for d in link_domains + plain_domains if d]))

    # Scores
    u_score = urgency_score(subject_h or "", content.get("text_plain", ""))
    att_score = attachment_suspicion_score(content.get("attachments", []))
    mismatch_from_links = link_domain_mismatch(content["links_in_html"], from_domain)
    mismatch_visible_href = visible_vs_href_mismatch(content["links_in_html"])

    # Señales booleanas
    from_vs_replyto_mismatch = (
        bool(from_domain)
        and bool(reply_to_domain)
        and not domains_related(from_domain, reply_to_domain)
    )
    from_vs_returnpath_mismatch = (
        bool(from_domain)
        and bool(return_path_domain)
        and not domains_related(from_domain, return_path_domain)
    )

    features = {
        "from": from_h,
        "from_domain": from_domain,
        "reply_to": reply_to_h,
        "reply_to_domain": reply_to_domain,
        "return_path": return_path_h,
        "return_path_domain": return_path_domain,
        "subject": subject_h,
        "date": headers.get("Date"),
        "message_id": msgid_h,
        "message_id_domain": msgid_domain,
        "origin_ip": origin_ip,
        "received_count": len(received_list),

        "spf_result": spf,     # "pass" | "fail" | None
        "dkim_result": dkim,   # "pass" | "fail" | None
        "dmarc_result": dmarc, # "pass" | "fail" | None

        "all_link_domains": all_domains,
        "link_domains_html": link_domains,
        "link_domains_text": plain_domains,
        "links_in_html_raw": content["links_in_html"],

        "urgency_score": u_score,                  # 0..5
        "attachment_suspicion_score": att_score,   # 0..6
        "from_vs_replyto_mismatch": from_vs_replyto_mismatch,
        "from_vs_returnpath_mismatch": from_vs_returnpath_mismatch,
        "link_domain_mismatch": mismatch_from_links,
        "visible_vs_href_mismatch": mismatch_visible_href,

        # Contadores útiles
        "attachment_count": len(content.get("attachments", [])),
        "url_count_text": len(content.get("urls_in_text", [])),
        "url_count_html": len(content.get("links_in_html", [])),
    }

    # Score heurístico simple (ejemplo para V1; calibra con tus datos)
    risk_score = 0
    risk_score += 3 if features["from_vs_returnpath_mismatch"] else 0
    risk_score += 2 if features["from_vs_replyto_mismatch"] else 0
    risk_score += 3 if (spf == "fail" or dkim == "fail" or dmarc == "fail") else 0
    risk_score += 2 if features["link_domain_mismatch"] else 0
    risk_score += 2 if features["visible_vs_href_mismatch"] else 0
    risk_score += features["attachment_suspicion_score"] // 2
    risk_score += 1 if features["urgency_score"] >= 3 else 0

    features["risk_score_v1"] = int(risk_score)
    return features


def extract_all(path: str) -> Dict[str, Any]:
    msg = parse_eml(path)
    headers = extract_headers(msg)
    content = extract_bodies_and_urls(msg)
    feats = build_features(headers, content)
    return {
        "headers": headers,
        "content": {
            "text_plain": content["text_plain"][:4000],  # evita JSON gigante
            "text_html_snippet": content["text_html"][:4000],
            "urls_in_text": content["urls_in_text"],
            "links_in_html": content["links_in_html"],
        },
        "attachments": content["attachments"],
        "features": feats
    }


# ----------------------------
# CLI
# ----------------------------

def main():
    path = input("Ingrese el PATH del archivo .eml: ")
    data = extract_all(path)
    print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
