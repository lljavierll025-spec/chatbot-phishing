# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Dict, Tuple, Any, List
from .eml_feature_extractor import extract_all
from ..models.loader import load_artifact

def _compose_text_for_model(eml: Dict[str, Any]) -> str:
    feats = eml.get("features", {}) or {}
    content = eml.get("content", {}) or {}
    subject = feats.get("subject") or ""
    body = content.get("text_plain") or content.get("text_html_snippet") or ""
    return f"{subject}\n\n{body}".strip()

def _collect_flags(feats: Dict[str, Any]) -> Tuple[int, List[str]]:
    exp: List[str] = []
    flags = 0
    if feats.get("visible_vs_href_mismatch"):
        exp.append("El texto del enlace no coincide con el destino real.")
        flags += 1
    if feats.get("from_vs_returnpath_mismatch"):
        exp.append("Return-Path diferente al dominio del remitente.")
        flags += 1
    if feats.get("from_vs_replyto_mismatch"):
        exp.append("Reply-To diferente al remitente.")
        flags += 1
    auth_fail = (feats.get("spf_result") == "fail") or (feats.get("dkim_result") == "fail") or (feats.get("dmarc_result") == "fail")
    if auth_fail:
        exp.append("Autenticación (SPF/DKIM/DMARC) fallida.")
        flags += 1
    if (feats.get("urgency_score") or 0) >= 3:
        exp.append("Lenguaje urgente.")
    if (feats.get("attachment_suspicion_score") or 0) >= 3:
        exp.append("Adjunto potencialmente riesgoso.")
    return flags, exp

def analyze_eml_hybrid(path_eml: str,
                       weights: Tuple[float, float, float] = (0.7, 0.2, 0.1),
                       green_max: float = 0.30,
                       yellow_max: float = 0.70) -> Dict[str, Any]:
    """
    Ensamble híbrido (Opción B):
      final_score = w1 * p_model + w2 * norm(risk_score_v1) + w3 * norm(flags)
    Devuelve un dict con: prediccion, prob_modelo, score_final, umbral_modelo, nivel, explicacion, resumen.
    """
    # 1) Extrae todo del .eml
    eml = extract_all(path_eml)
    feats = eml.get("features", {}) or {}
    # 2) Carga modelo y umbral
    pipeline, thr, _meta = load_artifact()
    # 3) Texto para el modelo y probabilidad
    text = _compose_text_for_model(eml)
    # Importante: si tu pipeline NO incluye preprocesado dentro, asegúrate de aplicar el mismo preprocesado del entrenamiento aquí.
    prob = float(pipeline.predict_proba([text])[0, 1])
    # 4) Señales del extractor
    risk = float(feats.get("risk_score_v1", 0.0))
    flags_count, explanation = _collect_flags(feats)
    # 5) Normalización simple
    norm_risk = min(max(risk / 10.0, 0.0), 1.0)       # asume risk_score_v1 en 0..10
    norm_flags = min(max(flags_count / 4.0, 0.0), 1.0) # 4 flags “duros” en _collect_flags
    w1, w2, w3 = weights
    final_score = w1 * prob + w2 * norm_risk + w3 * norm_flags
    final_score = float(min(max(final_score, 0.0), 1.0))
    # 6) Predicción y semáforo
    # pred = int(final_score >= thr)
    prediccion = ""
    if final_score < green_max:
        nivel = "verde"
        prediccion = "Legítimo"
    elif final_score < yellow_max:
        nivel = "amarillo"
        prediccion = "Sospechoso"
    else:
        nivel = "rojo"
        prediccion = "Phishing"
    # 7) Resumen técnico breve
    resumen = {
        "dominios_enlaces": feats.get("all_link_domains", []) or [],
        "spf/dkim/dmarc": (feats.get("spf_result"), feats.get("dkim_result"), feats.get("dmarc_result")),
        "adjuntos": eml.get("attachments", []) or [],
        "links_detalle": feats.get("links_in_html_raw", []) or []
    }

    return {
        "prediccion": prediccion,
        "prob_modelo": prob,
        "score_final": final_score,
        "umbral_modelo": thr,
        "nivel": nivel,
        "explicacion": explanation[:6],
        "resumen": resumen
    }

__all__ = ["analyze_eml_hybrid"]
