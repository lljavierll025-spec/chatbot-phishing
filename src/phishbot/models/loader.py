from __future__ import annotations
from pathlib import Path
import os
import joblib
from typing import Tuple, Any, Dict

def _default_model_path() -> Path:
    """
    Devuelve la ruta por defecto del artefacto del modelo.
    Busca PHISHBOT_MODEL_PATH en el entorno; si no está, usa models/artifacts/phishing_detector_pipeline.pkl
    """
    env_path = os.getenv("PHISHBOT_MODEL_PATH")
    if env_path:
        return Path(env_path).expanduser().resolve()
    # Este archivo está en: src/phishbot/models/loader.py
    # Raíz del proyecto = 3 niveles arriba.
    project_root = Path(__file__).resolve().parents[3]
    return project_root / "models" / "artifacts" / "phishing_detector_pipeline.pkl"

def load_artifact(path: Path | None = None) -> Tuple[Any, float, Dict]:
    """
    Carga el artefacto del modelo (.pkl) y devuelve:
        - pipeline (scikit-learn)
        - optimal_threshold (float, por defecto 0.5 si no está presente)
        - metadata (dict opcional)
    """
    model_path = Path(path) if path else _default_model_path()
    data = joblib.load(model_path)
    pipeline = data["pipeline"]
    thr = float(data.get("optimal_threshold", 0.5))
    meta = data.get("metadata", {})
    return pipeline, thr, meta

__all__ = ["load_artifact"]
