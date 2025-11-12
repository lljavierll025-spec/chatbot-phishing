# -*- coding: utf-8 -*-
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    roc_auc_score, average_precision_score, precision_recall_curve,
    roc_curve
)
import joblib
import re
import matplotlib.pyplot as plt
from datetime import datetime
import warnings

warnings.filterwarnings('ignore')


class PhishingDetectorTrainer:
    def __init__(self, csv_path):
        """
        Inicializa el entrenador del modelo de detección de phishing.

        Args:
            csv_path: Ruta al archivo CSV con los datos etiquetados
        """
        self.csv_path = csv_path
        self.pipeline = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.texts = None
        self.labels = None
        self.optimal_threshold = 0.5

    def load_data(self):
        """Carga y prepara los datos del CSV."""
        print("[Datos] Cargando datos...")
        df = pd.read_csv(self.csv_path)

        print(f"✓ Dataset cargado: {len(df)} registros")
        print(f"✓ Columnas: {list(df.columns)}")

        # Detectar automáticamente las columnas
        text_col = None
        label_col = None

        for col in df.columns:
            if df[col].dtype == 'object' and text_col is None:
                text_col = col
            elif label_col is None:
                label_col = col

        if text_col is None or label_col is None:
            raise ValueError(
                "No se pudieron detectar las columnas. Asegúrate de que el CSV tenga una columna de texto y una de etiquetas.")

        print(f"✓ Columna de texto: '{text_col}'")
        print(f"✓ Columna de etiquetas: '{label_col}'")

        # Extraer textos y etiquetas
        self.texts = df[text_col].astype(str)

        # Normalizar etiquetas
        labels = df[label_col].astype(str).str.lower()
        self.labels = labels.map(lambda x: 1 if x in ['phishing', '1', '1.0'] else 0)

        # Verificar valores nulos
        if self.texts.isnull().any():
            print("⚠️  Advertencia: Se encontraron valores nulos en los textos. Se eliminarán.")
            valid_idx = ~self.texts.isnull()
            self.texts = self.texts[valid_idx]
            self.labels = self.labels[valid_idx]

        # Distribución de clases
        phishing_count = self.labels.sum()
        legitimate_count = len(self.labels) - phishing_count
        phishing_pct = phishing_count / len(self.labels) * 100

        print(f"\n[Métricas] Distribución de clases:")
        print(f"   • Phishing: {phishing_count} ({phishing_pct:.1f}%)")
        print(f"   • Legítimos: {legitimate_count} ({100 - phishing_pct:.1f}%)")

        # Advertir sobre desbalance
        if phishing_pct < 20 or phishing_pct > 80:
            print(f"   ⚠️  Desbalance detectado. Se aplicará class_weight='balanced'")

        return self.texts, self.labels

    def preprocess_text(self, text):
        """
        Preprocesa el texto para mejorar la extracción de características.

        Args:
            text: Texto a preprocesar
        """
        text = text.lower()
        text = re.sub(r'http\S+|www\.\S+', ' url ', text)
        text = re.sub(r'\S+@\S+', ' email ', text)
        text = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', ' tarjeta ', text)
        text = re.sub(r'[^a-záéíóúñü\s\.\,\!\?]', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    def split_data(self, test_size=0.2, random_state=42):
        """Divide los datos en conjuntos de entrenamiento y prueba."""
        print(f"\n[Métricas] Dividiendo datos (test size: {test_size * 100}%)...")

        # Preprocesar textos
        processed_texts = self.texts.apply(self.preprocess_text)

        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            processed_texts,
            self.labels,
            test_size=test_size,
            random_state=random_state,
            stratify=self.labels
        )

        print(f"✓ Entrenamiento: {len(self.X_train)} muestras")
        print(f"✓ Prueba: {len(self.X_test)} muestras")

    def create_pipeline(self, max_features=5000, ngram_range=(1, 2), C=1.0):
        """
        Crea el pipeline completo con TF-IDF + Logistic Regression.

        Args:
            max_features: Número máximo de características
            ngram_range: Rango de n-gramas
            C: Parámetro de regularización (menor = más regularización)
        """
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                max_features=max_features,
                ngram_range=ngram_range,
                min_df=2,
                max_df=0.95,
                sublinear_tf=True
            )),
            ('classifier', LogisticRegression(
                max_iter=1000,
                class_weight='balanced',
                random_state=42,
                solver='lbfgs',
                C=C
            ))
        ])

        print(f"\n[Pipeline] Pipeline creado:")
        print(f"   • Vectorizador: TF-IDF")
        print(f"   • Max features: {max_features}")
        print(f"   • N-grams: {ngram_range}")
        print(f"   • Clasificador: Logistic Regression (balanced)")
        print(f"   • Regularización C: {C}")

    def cross_validate(self, n_splits=5):
        """
        Realiza validación cruzada estratificada.

        Args:
            n_splits: Número de particiones para K-Fold
        """
        print(f"\n[Validación] Validación cruzada ({n_splits}-Fold)...")

        cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

        # Preparar datos
        processed_texts = self.texts.apply(self.preprocess_text)

        # Evaluar con diferentes métricas
        scoring_metrics = {
            'accuracy': 'accuracy',
            'precision': 'precision',
            'recall': 'recall',
            'f1': 'f1',
            'roc_auc': 'roc_auc'
        }

        results = {}
        for metric_name, metric in scoring_metrics.items():
            scores = cross_val_score(
                self.pipeline,
                processed_texts,
                self.labels,
                cv=cv,
                scoring=metric,
                n_jobs=-1
            )
            results[metric_name] = scores

        print(f"\n[Métricas] Resultados de Validación Cruzada:")
        print("-" * 60)
        for metric_name, scores in results.items():
            print(f"{metric_name.capitalize():12} : {scores.mean():.4f} (+/- {scores.std():.4f})")

        return results

    def train_model(self):
        """Entrena el pipeline completo."""
        print(f"\n[Modelo] Entrenando modelo...")

        self.pipeline.fit(self.X_train, self.y_train)
        print("✓ Pipeline entrenado exitosamente")

    def find_optimal_threshold(self):
        """
        Encuentra el umbral óptimo que maximiza F1-Score.
        """
        print(f"\n[Objetivo] Buscando umbral óptimo...")

        y_probs = self.pipeline.predict_proba(self.X_test)[:, 1]
        precision, recall, thresholds = precision_recall_curve(self.y_test, y_probs)

        # Calcular F1 para cada umbral
        f1_scores = 2 * (precision * recall) / (precision + recall + 1e-10)
        optimal_idx = np.argmax(f1_scores)

        self.optimal_threshold = thresholds[optimal_idx] if optimal_idx < len(thresholds) else 0.5

        print(f"✓ Umbral óptimo encontrado: {self.optimal_threshold:.4f}")
        print(f"   • F1-Score con umbral óptimo: {f1_scores[optimal_idx]:.4f}")
        print(f"   • Precision: {precision[optimal_idx]:.4f}")
        print(f"   • Recall: {recall[optimal_idx]:.4f}")

        return self.optimal_threshold

    def evaluate_model(self, use_optimal_threshold=True):
        """
        Evalúa el modelo con métricas completas.

        Args:
            use_optimal_threshold: Si usar el umbral óptimo encontrado
        """
        print("\n[Evaluación] Evaluando modelo...")

        # Predicciones
        y_probs = self.pipeline.predict_proba(self.X_test)[:, 1]

        if use_optimal_threshold:
            threshold = self.optimal_threshold
            y_pred = (y_probs >= threshold).astype(int)
            print(f"   • Usando umbral: {threshold:.4f}")
        else:
            threshold = 0.5
            y_pred = self.pipeline.predict(self.X_test)
            print(f"   • Usando umbral por defecto: {threshold}")

        # Métricas básicas
        accuracy = accuracy_score(self.y_test, y_pred)

        # Métricas avanzadas
        roc_auc = roc_auc_score(self.y_test, y_probs)
        pr_auc = average_precision_score(self.y_test, y_probs)

        print(f"\n{'=' * 60}")
        print(f"RESULTADOS DE EVALUACIÓN")
        print(f"{'=' * 60}")
        print(f"\n[Objetivo] Métricas Generales:")
        print(f"   • Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)")
        print(f"   • ROC-AUC: {roc_auc:.4f}")
        print(f"   • PR-AUC (Precision-Recall): {pr_auc:.4f} ⭐")

        print(f"\n[Métricas] Reporte de Clasificación:")
        print("-" * 60)
        print(classification_report(
            self.y_test,
            y_pred,
            target_names=['Legítimo', 'Phishing'],
            digits=4
        ))

        print(f"[Análisis] Matriz de Confusión:")
        print("-" * 60)
        cm = confusion_matrix(self.y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()

        print(f"                  Predicho")
        print(f"                Legítimo  Phishing")
        print(f"Real Legítimo    {tn:>6}    {fp:>6}")
        print(f"     Phishing    {fn:>6}    {tp:>6}")
        print()
        print(f"   • Verdaderos Negativos (TN): {tn}")
        print(f"   • Falsos Positivos (FP): {fp} - Legítimos marcados como phishing")
        print(f"   • Falsos Negativos (FN): {fn} - ⚠️ Phishing no detectado")
        print(f"   • Verdaderos Positivos (TP): {tp}")

        # Interpretación
        print(f"\n[Nota] Interpretación:")
        if fn > 0:
            print(f"   ⚠️  {fn} emails de phishing NO fueron detectados (peligroso)")
        if fp > 0:
            print(f"   ⚠️  {fp} emails legítimos fueron marcados como phishing (molesto)")

        # Características importantes
        self.show_important_features(n=15)

        return {
            'accuracy': accuracy,
            'roc_auc': roc_auc,
            'pr_auc': pr_auc,
            'threshold': threshold
        }

    def show_important_features(self, n=15):
        """Muestra las características más importantes del modelo."""
        print(f"\n[Características] Top {n} características más importantes:")
        print("-" * 60)

        # Extraer componentes del pipeline
        vectorizer = self.pipeline.named_steps['tfidf']
        classifier = self.pipeline.named_steps['classifier']

        feature_names = vectorizer.get_feature_names_out()
        coef = classifier.coef_[0]

        # Phishing indicators
        top_phishing_idx = np.argsort(coef)[-n:][::-1]
        print("\n[Indicadores] Indicadores de PHISHING:")
        for idx in top_phishing_idx:
            print(f"   • '{feature_names[idx]}': {coef[idx]:.4f}")

        # Legitimate indicators
        top_legitimate_idx = np.argsort(coef)[:n]
        print("\n✅ Indicadores de LEGÍTIMO:")
        for idx in top_legitimate_idx:
            print(f"   • '{feature_names[idx]}': {coef[idx]:.4f}")

    def plot_metrics(self, save_path=None):
        """
        Genera gráficos de ROC y Precision-Recall curves.

        Args:
            save_path: Ruta para guardar las gráficas (opcional)
        """
        try:
            y_probs = self.pipeline.predict_proba(self.X_test)[:, 1]

            fig, axes = plt.subplots(1, 2, figsize=(14, 5))

            # ROC Curve
            fpr, tpr, _ = roc_curve(self.y_test, y_probs)
            roc_auc = roc_auc_score(self.y_test, y_probs)

            axes[0].plot(fpr, tpr, color='darkorange', lw=2,
                         label=f'ROC curve (AUC = {roc_auc:.4f})')
            axes[0].plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random')
            axes[0].set_xlim([0.0, 1.0])
            axes[0].set_ylim([0.0, 1.05])
            axes[0].set_xlabel('False Positive Rate')
            axes[0].set_ylabel('True Positive Rate')
            axes[0].set_title('ROC Curve')
            axes[0].legend(loc="lower right")
            axes[0].grid(alpha=0.3)

            # Precision-Recall Curve
            precision, recall, thresholds = precision_recall_curve(self.y_test, y_probs)
            pr_auc = average_precision_score(self.y_test, y_probs)

            axes[1].plot(recall, precision, color='blue', lw=2,
                         label=f'PR curve (AUC = {pr_auc:.4f})')
            axes[1].axhline(y=self.y_test.mean(), color='red', linestyle='--',
                            label=f'Baseline ({self.y_test.mean():.4f})')
            axes[1].set_xlim([0.0, 1.0])
            axes[1].set_ylim([0.0, 1.05])
            axes[1].set_xlabel('Recall')
            axes[1].set_ylabel('Precision')
            axes[1].set_title('Precision-Recall Curve')
            axes[1].legend(loc="lower left")
            axes[1].grid(alpha=0.3)

            plt.tight_layout()

            if save_path:
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
                print(f"\n[Métricas] Gráficas guardadas en: {save_path}")
            else:
                plt.show()

        except Exception as e:
            print(f"\n⚠️  No se pudieron generar las gráficas: {e}")
            print("   (matplotlib puede no estar disponible)")

    def save_pipeline(self, filepath='phishing_detector_pipeline.pkl'):
        """
        Guarda el pipeline completo en un único archivo.

        Args:
            filepath: Ruta del archivo de salida
        """
        print(f"\n[Guardado] Guardando pipeline completo...")

        # Incluir el umbral óptimo en el pipeline
        pipeline_data = {
            'pipeline': self.pipeline,
            'optimal_threshold': self.optimal_threshold,
            'training_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'feature_count': len(self.pipeline.named_steps['tfidf'].get_feature_names_out())
        }

        joblib.dump(pipeline_data, filepath)

        print(f"✓ Pipeline guardado en: {filepath}")
        print(f"   • Umbral óptimo: {self.optimal_threshold:.4f}")
        print(f"   • Características: {pipeline_data['feature_count']}")
        print(f"   • Fecha: {pipeline_data['training_date']}")

    @staticmethod
    def load_pipeline(filepath='phishing_detector_pipeline.pkl'):
        """
        Carga un pipeline guardado.

        Args:
            filepath: Ruta del archivo del pipeline

        Returns:
            Diccionario con pipeline y metadatos
        """
        pipeline_data = joblib.load(filepath)
        print(f"✓ Pipeline cargado desde: {filepath}")
        print(f"   • Entrenado: {pipeline_data.get('training_date', 'N/A')}")
        print(f"   • Umbral óptimo: {pipeline_data.get('optimal_threshold', 0.5):.4f}")
        return pipeline_data

    def predict_sample(self, text, use_optimal_threshold=True):
        """
        Realiza una predicción sobre un texto.

        Args:
            text: Texto a clasificar
            use_optimal_threshold: Si usar el umbral óptimo
        """
        if self.pipeline is None:
            raise ValueError("El modelo debe ser entrenado antes de hacer predicciones")

        processed = self.preprocess_text(text)
        probability = self.pipeline.predict_proba([processed])[0]

        threshold = self.optimal_threshold if use_optimal_threshold else 0.5
        prediction = 1 if probability[1] >= threshold else 0

        return {
            'prediccion': 'Phishing' if prediction == 1 else 'Legítimo',
            'probabilidad_phishing': probability[1],
            'probabilidad_legitimo': probability[0],
            'umbral_usado': threshold,
            'confianza': max(probability)
        }


def main():
    """Función principal para ejecutar el entrenamiento."""
    print("=" * 60)
    print("ENTRENADOR DE MODELO ANTI-PHISHING [VERSIÓN AVANZADA]")
    print("Pipeline: TF-IDF + Logistic Regression (Balanced)")
    print("=" * 60)

    csv_path = input("\n[Archivo] Ingresa la ruta del archivo CSV: ").strip()

    try:
        # Inicializar entrenador
        trainer = PhishingDetectorTrainer(csv_path)

        # Cargar datos
        trainer.load_data()

        # Dividir datos
        trainer.split_data(test_size=0.2)

        # Crear pipeline
        trainer.create_pipeline(max_features=5000, ngram_range=(1, 2))

        # Validación cruzada (opcional)
        cv_option = input("\n[Validación] ¿Realizar validación cruzada? (s/n): ").strip().lower()
        if cv_option == 's':
            trainer.cross_validate(n_splits=5)

        # Entrenar modelo
        trainer.train_model()

        # Encontrar umbral óptimo
        trainer.find_optimal_threshold()

        # Evaluar modelo
        metrics = trainer.evaluate_model(use_optimal_threshold=True)

        # Generar gráficas
        plot_option = input("\n[Métricas] ¿Generar gráficas ROC y PR? (s/n): ").strip().lower()
        if plot_option == 's':
            save_plot = input("   ¿Guardar gráficas? (s/n): ").strip().lower()
            if save_plot == 's':
                trainer.plot_metrics(save_path='phishing_metrics.png')
            else:
                trainer.plot_metrics()

        # Guardar pipeline
        print("\n" + "=" * 60)
        save_option = input("[Guardado] ¿Deseas guardar el pipeline? (s/n): ").strip().lower()
        if save_option == 's':
            filename = input("Nombre del archivo (default: phishing_detector_pipeline.pkl): ").strip()
            filename = filename if filename else 'phishing_detector_pipeline.pkl'
            trainer.save_pipeline(filename)

        # Probar con ejemplos
        print("\n" + "=" * 60)
        test_option = input("[Pruebas] ¿Deseas probar el modelo con ejemplos? (s/n): ").strip().lower()
        if test_option == 's':
            while True:
                text = input("\nIngresa un texto para clasificar (o 'salir' para terminar): ").strip()
                if text.lower() == 'salir':
                    break

                result = trainer.predict_sample(text, use_optimal_threshold=True)
                print(f"\n[Análisis] Resultado:")
                print(f"   • Predicción: {result['prediccion']}")
                print(f"   • Probabilidad Phishing: {result['probabilidad_phishing'] * 100:.2f}%")
                print(f"   • Probabilidad Legítimo: {result['probabilidad_legitimo'] * 100:.2f}%")
                print(f"   • Umbral usado: {result['umbral_usado']:.4f}")
                print(f"   • Confianza: {result['confianza'] * 100:.2f}%")

        print("\n✅ Proceso completado exitosamente!")
        print("\n[Checklist] Recomendaciones:")
        print("   • PR-AUC es la métrica más importante para phishing")
        print("   • Revisa los falsos negativos (phishing no detectado)")
        print("   • Ajusta el umbral según tu caso de uso")

    except FileNotFoundError:
        print(f"❌ Error: No se encontró el archivo '{csv_path}'")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
