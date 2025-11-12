"""
Generador de correos electrónicos sintéticos en español para entrenamiento de modelos ML.
Crea correos de phishing y legítimos con alta diversidad y realismo.
"""

import pandas as pd
import random
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Tuple
import logging


class SyntheticEmailGenerator:
    """Generador de correos electrónicos sintéticos."""

    def __init__(self, seed: int = 42):
        """
        Inicializar el generador.

        Args:
            seed: Semilla para reproducibilidad
        """
        random.seed(seed)

        # Configurar logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # Dominios ficticios para phishing (sospechosos)
        self.phishing_domains = [
            'mi-banco-seguro.test',
            'verificacion-cuenta.test',
            'seguridad-bancaria.test',
            'actualizar-datos.test',
            'premio-ganador.test',
            'ofertas-exclusivas.test',
            'alerta-seguridad.test',
            'confirmar-identidad.test',
            'reembolso-fiscal.test',
            'sorteo-oficial.test',
            'banco-virtual.test',
            'pago-pendiente.test',
            'cuenta-bloqueada.test',
            'verificar-ahora.test',
            'soporte-tecnico.test'
        ]

        # Dominios ficticios legítimos
        self.legitimate_domains = [
            'mi-empresa.test',
            'universidad-ejemplo.test',
            'tienda-online.test',
            'newsletter-tech.test',
            'correo-personal.test',
            'oficina-virtual.test',
            'equipo-proyecto.test',
            'comunidad-usuarios.test',
            'plataforma-cursos.test',
            'servicio-cliente.test',
            'empresa-ejemplo.test',
            'corporativo-test.test',
            'organizacion-demo.test',
            'compania-ficticia.test',
            'proveedor-ejemplo.test'
        ]

        # Nombres ficticios
        self.nombres = [
            'Carlos', 'María', 'Juan', 'Ana', 'Pedro', 'Laura', 'Miguel', 'Carmen',
            'José', 'Isabel', 'Antonio', 'Rosa', 'Francisco', 'Marta', 'Luis', 'Elena',
            'Javier', 'Patricia', 'Manuel', 'Lucía', 'David', 'Sara', 'Jorge', 'Paula'
        ]

        self.apellidos = [
            'García', 'Rodríguez', 'Martínez', 'López', 'González', 'Pérez', 'Sánchez',
            'Ramírez', 'Torres', 'Flores', 'Rivera', 'Gómez', 'Díaz', 'Cruz', 'Morales',
            'Reyes', 'Ortiz', 'Gutiérrez', 'Chávez', 'Ruiz', 'Hernández', 'Jiménez'
        ]

        # Montos comunes
        self.montos = [
            '50', '100', '250', '500', '1,000', '2,500', '5,000',
            '10,000', '25,000', '50,000', '100,000'
        ]

        # Números de orden/cuenta/referencia
        self.generate_random_numbers()

    def generate_random_numbers(self):
        """Generar números aleatorios para usar en correos."""
        self.numeros_orden = [f"{random.randint(100000, 999999)}" for _ in range(100)]
        self.numeros_cuenta = [f"****{random.randint(1000, 9999)}" for _ in range(50)]
        self.numeros_referencia = [f"REF-{random.randint(10000, 99999)}" for _ in range(100)]

    def get_random_name(self) -> str:
        """Obtener nombre completo aleatorio."""
        return f"{random.choice(self.nombres)} {random.choice(self.apellidos)}"

    def get_random_email(self, domain: str) -> str:
        """Generar email aleatorio con dominio dado."""
        prefixes = ['soporte', 'info', 'contacto', 'admin', 'noreply',
                    'servicio', 'ayuda', 'notificaciones', 'alertas', 'equipo']
        return f"{random.choice(prefixes)}@{domain}"

    def add_typos(self, text: str, probability: float = 0.15) -> str:
        """
        Añadir errores ortográficos ocasionales.

        Args:
            text: Texto original
            probability: Probabilidad de error por palabra

        Returns:
            Texto con posibles errores
        """
        if random.random() > 0.3:  # Solo 30% de correos tendrán errores
            return text

        # Errores comunes en español
        replacements = {
            'verificar': 'berificar',
            'cuenta': 'quenta',
            'banco': 'vanco',
            'hacer': 'acer',
            'haber': 'aver',
            'hola': 'ola',
            'urgente': 'urjente',
            'inmediatamente': 'inmediatamnte',
            'confirmación': 'confirmacion',
            'transacción': 'transaccion',
            'información': 'informacion',
            'atención': 'atencion',
        }

        words = text.split()
        for i, word in enumerate(words):
            if random.random() < probability:
                word_lower = word.lower()
                for original, typo in replacements.items():
                    if original in word_lower:
                        words[i] = word.replace(original, typo)
                        break

        return ' '.join(words)

    def generate_phishing_email(self) -> Dict[str, str]:
        """Generar un correo de phishing sintético."""

        # Seleccionar tipo de phishing
        phishing_type = random.choice([
            'password_reset',
            'fake_payment',
            'security_alert',
            'prize_winner',
            'account_suspended',
            'urgent_action',
            'fake_invoice',
            'tax_refund',
            'delivery_problem',
            'too_good_offer'
        ])

        domain = random.choice(self.phishing_domains)
        sender = self.get_random_email(domain)

        # Generar contenido según tipo
        if phishing_type == 'password_reset':
            subject, body = self._generate_password_reset_phishing()
        elif phishing_type == 'fake_payment':
            subject, body = self._generate_fake_payment_phishing()
        elif phishing_type == 'security_alert':
            subject, body = self._generate_security_alert_phishing()
        elif phishing_type == 'prize_winner':
            subject, body = self._generate_prize_winner_phishing()
        elif phishing_type == 'account_suspended':
            subject, body = self._generate_account_suspended_phishing()
        elif phishing_type == 'urgent_action':
            subject, body = self._generate_urgent_action_phishing()
        elif phishing_type == 'fake_invoice':
            subject, body = self._generate_fake_invoice_phishing()
        elif phishing_type == 'tax_refund':
            subject, body = self._generate_tax_refund_phishing()
        elif phishing_type == 'delivery_problem':
            subject, body = self._generate_delivery_problem_phishing()
        else:  # too_good_offer
            subject, body = self._generate_too_good_offer_phishing()

        # Decidir si añadir errores ortográficos
        if random.random() < 0.4:  # 40% con errores
            subject = self.add_typos(subject)
            body = self.add_typos(body)

        # Crear email completo
        full_text = f"{subject}\n\n{body}"

        return {
            'text': full_text,
            'subject': subject,
            'body': body,
            'from': sender,
            'label': 'phishing',
            'type': phishing_type
        }

    def _generate_password_reset_phishing(self) -> Tuple[str, str]:
        """Generar phishing de restablecimiento de contraseña."""
        subjects = [
            "URGENTE: Restablece tu contraseña ahora",
            "Solicitud de cambio de contraseña - Acción requerida",
            "Tu contraseña expirará en 24 horas",
            "Confirma tu identidad - Cambio de contraseña",
            "Alerta: Intento de acceso no autorizado a tu cuenta"
        ]

        bodies = [
            f"Estimado usuario,\n\nHemos detectado actividad sospechosa en tu cuenta. Por tu seguridad, debes restablecer tu contraseña inmediatamente.\n\nHaz clic aquí para restablecer: http://{random.choice(self.phishing_domains)}/reset\n\nSi no lo haces en las próximas 24 horas, tu cuenta será suspendida.\n\nAtentamente,\nEquipo de Seguridad",

            f"Hola,\n\nTu contraseña está a punto de expirar. Para mantener el acceso a tu cuenta, actualízala ahora.\n\nActualizar contraseña: http://{random.choice(self.phishing_domains)}/update\n\nEste enlace expira en 12 horas.\n\nGracias,\nSoporte Técnico",

            f"ATENCIÓN URGENTE\n\nAlguien intentó acceder a tu cuenta desde una ubicación desconocida. Por tu seguridad, cambia tu contraseña de inmediato.\n\nCambiar ahora: http://{random.choice(self.phishing_domains)}/secure\n\nNo ignores este mensaje.\n\nEquipo de Seguridad",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_fake_payment_phishing(self) -> Tuple[str, str]:
        """Generar phishing de pago falso."""
        monto = random.choice(self.montos)
        orden = random.choice(self.numeros_orden)

        subjects = [
            f"Confirmación de pago: ${monto} MXN",
            f"Pago rechazado - Orden #{orden}",
            f"Actualiza tu método de pago - ${monto}",
            f"Cargo pendiente de ${monto} - Acción requerida",
            f"Problema con tu pago de ${monto}"
        ]

        bodies = [
            f"Hola,\n\nTu pago de ${monto} MXN ha sido rechazado. Actualiza tu información de pago para completar la transacción.\n\nOrden: {orden}\nMonto: ${monto} MXN\n\nActualizar método de pago: http://{random.choice(self.phishing_domains)}/pago\n\nSi no actualizas en 48 horas, tu pedido será cancelado.\n\nGracias.",

            f"Estimado cliente,\n\nHemos intentado procesar tu pago de ${monto} sin éxito. Tu tarjeta fue rechazada.\n\nPara evitar cargos adicionales, confirma tus datos aquí: http://{random.choice(self.phishing_domains)}/confirmar\n\nReferencia: {orden}\n\nEquipo de Pagos",

            f"CARGO PENDIENTE\n\nTienes un cargo pendiente de ${monto} MXN. Completa el pago ahora para evitar intereses.\n\nPagar ahora: http://{random.choice(self.phishing_domains)}/pagar\n\nTransacción: {orden}\n\nDepartamento de Cobranza",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_security_alert_phishing(self) -> Tuple[str, str]:
        """Generar phishing de alerta de seguridad."""
        cuenta = random.choice(self.numeros_cuenta)

        subjects = [
            "ALERTA: Actividad sospechosa detectada",
            "Tu cuenta ha sido comprometida",
            "Inicio de sesión desde dispositivo desconocido",
            "Verifica tu identidad inmediatamente",
            "URGENTE: Posible fraude en tu cuenta"
        ]

        bodies = [
            f"¡ALERTA DE SEGURIDAD!\n\nDetectamos un inicio de sesión sospechoso en tu cuenta {cuenta}.\n\nUbicación: Ciudad desconocida\nDispositivo: Desconocido\nFecha: {datetime.now().strftime('%d/%m/%Y')}\n\nSi no fuiste tú, verifica tu cuenta ahora: http://{random.choice(self.phishing_domains)}/verificar\n\nActúa inmediatamente.\n\nEquipo de Seguridad",

            f"Estimado usuario,\n\nHemos bloqueado tu cuenta {cuenta} por actividad inusual. Para desbloquearla, confirma tu identidad.\n\nConfirmar identidad: http://{random.choice(self.phishing_domains)}/desbloquear\n\nTienes 24 horas o tu cuenta será suspendida permanentemente.\n\nAtentamente,\nDepartamento de Seguridad",

            f"ATENCIÓN INMEDIATA REQUERIDA\n\nIntento de acceso no autorizado a tu cuenta. Detectamos actividad de múltiples ubicaciones simultáneamente.\n\nProtege tu cuenta: http://{random.choice(self.phishing_domains)}/proteger\n\nCuenta afectada: {cuenta}\n\nNo demores esta acción.\n\nCentro de Seguridad",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_prize_winner_phishing(self) -> Tuple[str, str]:
        """Generar phishing de premio ganador."""
        premio = random.choice(['100,000', '250,000', '500,000', '1,000,000'])

        subjects = [
            f"¡FELICIDADES! Ganaste ${premio} MXN",
            f"Eres el ganador de nuestro sorteo - ${premio}",
            f"Premio especial para ti: ${premio} MXN",
            f"Has sido seleccionado - Premio de ${premio}",
            f"SORTEO GANADOR: ${premio} te esperan"
        ]

        bodies = [
            f"¡FELICIDADES {self.get_random_name().split()[0].upper()}!\n\nHas sido seleccionado como GANADOR de nuestro sorteo anual.\n\nPREMIO: ${premio} MXN\n\nPara reclamar tu premio, ingresa tus datos aquí: http://{random.choice(self.phishing_domains)}/premio\n\nTienes 72 horas para reclamar o se asignará a otro participante.\n\n¡Enhorabuena!\nComité de Sorteos",

            f"Estimado participante,\n\n¡GANASTE! Tu número fue seleccionado en nuestro sorteo mensual.\n\nPremio: ${premio} MXN\nFolio: {random.choice(self.numeros_referencia)}\n\nReclama tu premio: http://{random.choice(self.phishing_domains)}/reclamar\n\nSolo necesitas confirmar tu identidad y el dinero será transferido.\n\nFelicidades,\nLotería Nacional Ficticia",

            f"¡INCREÍBLE NOTICIA!\n\nFuiste elegido entre miles de participantes para recibir ${premio} MXN.\n\nNo es broma. Es real. Confirma tus datos y recibe tu premio: http://{random.choice(self.phishing_domains)}/ganador\n\nOFERTA LIMITADA: Solo por 48 horas.\n\nSorteo Internacional",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_account_suspended_phishing(self) -> Tuple[str, str]:
        """Generar phishing de cuenta suspendida."""
        subjects = [
            "URGENTE: Tu cuenta será suspendida",
            "Cuenta bloqueada - Acción inmediata requerida",
            "Suspensión de cuenta en 24 horas",
            "Tu cuenta ha sido desactivada temporalmente",
            "AVISO: Cuenta pendiente de cierre"
        ]

        bodies = [
            f"Estimado usuario,\n\nTu cuenta será suspendida en 24 horas por falta de verificación.\n\nPara evitar la suspensión, verifica tu información ahora: http://{random.choice(self.phishing_domains)}/evitar-suspension\n\nSi no actúas, perderás acceso permanente.\n\nAtentamente,\nAdministración de Cuentas",

            f"AVISO IMPORTANTE\n\nTu cuenta ha sido marcada para cierre debido a inactividad. Para mantenerla activa, confirma tus datos.\n\nConfirmar cuenta: http://{random.choice(self.phishing_domains)}/mantener-activa\n\nTiempo restante: 12 horas\n\nDepartamento de Administración",

            f"Tu cuenta está en riesgo de suspensión permanente.\n\nMotivo: Información desactualizada\nAcción requerida: Actualizar datos\nPlazo: 24 horas\n\nActualizar ahora: http://{random.choice(self.phishing_domains)}/actualizar\n\nNo pierdas tu cuenta.\n\nSoporte",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_urgent_action_phishing(self) -> Tuple[str, str]:
        """Generar phishing de acción urgente."""
        subjects = [
            "ACCIÓN INMEDIATA REQUERIDA",
            "URGENTE: Responde en las próximas 2 horas",
            "ÚLTIMA OPORTUNIDAD - No ignores esto",
            "TIEMPO LIMITADO: Actúa ahora o pierde acceso",
            "CRÍTICO: Confirmación necesaria HOY"
        ]

        bodies = [
            f"ATENCIÓN URGENTE\n\nEsta es tu ÚLTIMA oportunidad para actualizar tu información. Si no respondes en 2 horas, tu cuenta será cerrada permanentemente.\n\nACTÚA AHORA: http://{random.choice(self.phishing_domains)}/urgente\n\nNo esperes más.\n\nEquipo de Emergencias",

            f"¡¡¡TIEMPO LIMITADO!!!\n\nSOLO TIENES HOY para completar la verificación de seguridad. Después de hoy, tu cuenta será ELIMINADA.\n\nVerificar AHORA: http://{random.choice(self.phishing_domains)}/hoy\n\nNo dejes pasar esta oportunidad.\n\nAdministración",

            f"ÚLTIMA ADVERTENCIA\n\nHas ignorado nuestros avisos previos. Esta es la ÚLTIMA vez que te contactamos.\n\nConfirma tu identidad en las próximas 3 horas: http://{random.choice(self.phishing_domains)}/ultima-oportunidad\n\nDespués de esto, no habrá más chances.\n\nDepartamento Legal",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_fake_invoice_phishing(self) -> Tuple[str, str]:
        """Generar phishing de factura falsa."""
        monto = random.choice(self.montos)
        factura = random.choice(self.numeros_referencia)

        subjects = [
            f"Factura #{factura} - ${monto} MXN",
            f"Pago vencido: Factura {factura}",
            f"Recibo de pago - ${monto}",
            f"Cargo automático procesado: ${monto}",
            f"Comprobante de transacción #{factura}"
        ]

        bodies = [
            f"Estimado cliente,\n\nSe ha generado una nueva factura a tu nombre:\n\nFactura: {factura}\nMonto: ${monto} MXN\nFecha de vencimiento: {(datetime.now() + timedelta(days=3)).strftime('%d/%m/%Y')}\n\nVer factura completa: http://{random.choice(self.phishing_domains)}/factura\n\nSi no reconoces este cargo, repórtalo inmediatamente.\n\nDepartamento de Facturación",

            f"Se ha procesado un cargo a tu tarjeta:\n\nMonto: ${monto} MXN\nConcepto: Renovación automática\nReferencia: {factura}\n\nSi no autorizaste este cargo, cancélalo aquí: http://{random.choice(self.phishing_domains)}/cancelar\n\nTienes 48 horas para disputar.\n\nEquipo de Pagos",

            f"AVISO DE COBRO\n\nFactura pendiente de pago:\n• Número: {factura}\n• Monto: ${monto} MXN\n• Estado: VENCIDA\n\nPagar ahora para evitar recargos: http://{random.choice(self.phishing_domains)}/pagar-factura\n\nInterés por mora: 5% mensual\n\nCobranza",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_tax_refund_phishing(self) -> Tuple[str, str]:
        """Generar phishing de reembolso fiscal."""
        monto = random.choice(['5,230', '8,450', '12,680', '15,900', '23,150'])

        subjects = [
            f"Reembolso de impuestos aprobado: ${monto} MXN",
            "Tienes un reembolso fiscal pendiente",
            f"Devolución de impuestos - ${monto}",
            "Solicitud de reembolso procesada exitosamente",
            f"Crédito fiscal disponible: ${monto} MXN"
        ]

        bodies = [
            f"Estimado contribuyente,\n\nSu declaración anual ha sido procesada y tiene derecho a un reembolso de ${monto} MXN.\n\nPara recibir su reembolso, confirme sus datos bancarios: http://{random.choice(self.phishing_domains)}/reembolso\n\nEl proceso toma 48 horas una vez confirmados los datos.\n\nServicio de Administración Tributaria Ficticia",

            f"REEMBOLSO APROBADO\n\nFelicidades, califica para un reembolso fiscal de ${monto} MXN.\n\nFolio: {random.choice(self.numeros_referencia)}\n\nReclamar reembolso: http://{random.choice(self.phishing_domains)}/reclamar-reembolso\n\nEste derecho expira en 30 días.\n\nHacienda Nacional Ficticia",

            f"Notificación de Reembolso\n\nDebe recibir un crédito fiscal de ${monto} MXN por su declaración del año anterior.\n\nActualice su información para el depósito: http://{random.choice(self.phishing_domains)}/actualizar-info\n\nSi no responde en 15 días, el reembolso se cancelará.\n\nDepartamento de Devoluciones",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_delivery_problem_phishing(self) -> Tuple[str, str]:
        """Generar phishing de problema de entrega."""
        paquete = random.choice(self.numeros_referencia)

        subjects = [
            f"Problema con tu entrega - Paquete #{paquete}",
            "Tu paquete no pudo ser entregado",
            f"Acción requerida: Envío {paquete}",
            "Confirmación de dirección necesaria",
            f"Paquete retenido en aduana - {paquete}"
        ]

        bodies = [
            f"Hola,\n\nNo pudimos entregar tu paquete por dirección incorrecta.\n\nNúmero de rastreo: {paquete}\nIntentos de entrega: 2\n\nActualiza tu dirección aquí: http://{random.choice(self.phishing_domains)}/actualizar-direccion\n\nSi no actualizas en 48 horas, el paquete será devuelto.\n\nServicio de Paquetería Ficticia",

            f"PAQUETE RETENIDO\n\nTu envío {paquete} está retenido en nuestra bodega por falta de información.\n\nPara liberarlo, paga la tarifa de almacenamiento: $150 MXN\n\nPagar y recibir: http://{random.choice(self.phishing_domains)}/liberar-paquete\n\nDespués de 7 días será descartado.\n\nAlmacén de Paquetería",

            f"Notificación de Envío\n\nTu paquete {paquete} está en aduana. Se requiere el pago de impuestos de importación.\n\nMonto: $250 MXN\nPlazo: 5 días\n\nPagar impuestos: http://{random.choice(self.phishing_domains)}/pagar-impuestos\n\nAduana Nacional Ficticia",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_too_good_offer_phishing(self) -> Tuple[str, str]:
        """Generar phishing de oferta demasiado buena."""
        descuento = random.choice(['70%', '80%', '90%', '95%'])

        subjects = [
            f"¡OFERTA EXCLUSIVA! {descuento} de descuento SOLO HOY",
            f"ÚLTIMA OPORTUNIDAD: {descuento} OFF en todo",
            f"¡Increíble! {descuento} de descuento por tiempo limitado",
            f"Black Friday anticipado: {descuento} de descuento",
            f"REGALO ESPECIAL: {descuento} en tu próxima compra"
        ]

        bodies = [
            f"¡¡¡OFERTA IRREPETIBLE!!!\n\n{descuento} de descuento en TODOS los productos.\n\nSOLO POR HOY\nSOLO PARA TI\n\nEntra ahora: http://{random.choice(self.phishing_domains)}/oferta\n\nNo te lo pierdas. Esta oferta termina a medianoche.\n\nTienda Virtual Ficticia",

            f"Has sido seleccionado para nuestra MEGA VENTA VIP\n\nDescuento exclusivo: {descuento}\nTiempo limitado: 3 horas\n\nACCEDE AHORA: http://{random.choice(self.phishing_domains)}/vip-sale\n\nSolo para clientes especiales como tú.\n\nVentas Especiales",

            f"¡LIQUIDACIÓN TOTAL!\n\nTodo debe irse. {descuento} de descuento en absolutamente todo.\n\nMás un REGALO SORPRESA para los primeros 100 compradores.\n\nComprar ahora: http://{random.choice(self.phishing_domains)}/liquidacion\n\n¡No esperes! Se están agotando.\n\nOutlet Online",
        ]

        return random.choice(subjects), random.choice(bodies)

    def generate_legitimate_email(self) -> Dict[str, str]:
        """Generar un correo legítimo sintético."""

        # Seleccionar tipo de correo legítimo
        email_type = random.choice([
            'order_confirmation',
            'newsletter',
            'personal_email',
            'receipt',
            'meeting_reminder',
            'project_update',
            'welcome_message',
            'subscription_renewal',
            'support_response',
            'educational_content'
        ])

        domain = random.choice(self.legitimate_domains)
        sender = self.get_random_email(domain)

        # Generar contenido según tipo
        if email_type == 'order_confirmation':
            subject, body = self._generate_order_confirmation()
        elif email_type == 'newsletter':
            subject, body = self._generate_newsletter()
        elif email_type == 'personal_email':
            subject, body = self._generate_personal_email()
        elif email_type == 'receipt':
            subject, body = self._generate_receipt()
        elif email_type == 'meeting_reminder':
            subject, body = self._generate_meeting_reminder()
        elif email_type == 'project_update':
            subject, body = self._generate_project_update()
        elif email_type == 'welcome_message':
            subject, body = self._generate_welcome_message()
        elif email_type == 'subscription_renewal':
            subject, body = self._generate_subscription_renewal()
        elif email_type == 'support_response':
            subject, body = self._generate_support_response()
        else:  # educational_content
            subject, body = self._generate_educational_content()

        # Los correos legítimos generalmente NO tienen errores ortográficos
        # Solo un 5% podría tener algún pequeño error
        if random.random() < 0.05:
            body = self.add_typos(body, probability=0.05)

        # Crear email completo
        full_text = f"{subject}\n\n{body}"

        return {
            'text': full_text,
            'subject': subject,
            'body': body,
            'from': sender,
            'label': 'legitimate',
            'type': email_type
        }

    def _generate_order_confirmation(self) -> Tuple[str, str]:
        """Generar confirmación de pedido legítima."""
        orden = random.choice(self.numeros_orden)
        monto = random.choice(self.montos)

        subjects = [
            f"Confirmación de pedido #{orden}",
            f"Tu pedido ha sido recibido - Orden {orden}",
            f"Pedido confirmado: {orden}",
            f"Recibimos tu orden #{orden}",
        ]

        bodies = [
            f"Hola,\n\nGracias por tu compra. Tu pedido ha sido confirmado.\n\nDetalles del pedido:\n• Número de orden: {orden}\n• Total: ${monto} MXN\n• Fecha estimada de entrega: {(datetime.now() + timedelta(days=5)).strftime('%d de %B')}\n\nPuedes rastrear tu pedido en tu cuenta.\n\nGracias por tu preferencia,\nEquipo de Ventas",

            f"Estimado cliente,\n\nTu pedido {orden} ha sido procesado exitosamente.\n\nResumen:\n- Monto total: ${monto} MXN\n- Estado: En preparación\n- Envío estimado: 3-5 días hábiles\n\nTe notificaremos cuando tu pedido sea enviado.\n\nSaludos cordiales,\nTienda Online",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_newsletter(self) -> Tuple[str, str]:
        """Generar boletín informativo legítimo."""
        subjects = [
            "Boletín mensual - Novedades y actualizaciones",
            "Nuestro boletín de este mes",
            "Newsletter: Lo más destacado de la semana",
            "Actualizaciones y noticias de interés",
        ]

        bodies = [
            f"Hola,\n\nBienvenido a nuestro boletín mensual. Este mes compartimos:\n\n1. Nuevas funcionalidades en nuestra plataforma\n2. Artículos destacados sobre tecnología\n3. Próximos eventos y webinars\n4. Ofertas especiales para suscriptores\n\nGracias por ser parte de nuestra comunidad.\n\nUn saludo,\nEquipo Editorial",

            f"Estimado suscriptor,\n\nEn esta edición encontrarás:\n\n• Guías prácticas sobre seguridad digital\n• Consejos para mejorar tu productividad\n• Reseñas de herramientas útiles\n• Eventos comunitarios del mes\n\nEsperamos que esta información sea de tu interés.\n\nSaludos,\nEquipo de Contenido",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_personal_email(self) -> Tuple[str, str]:
        """Generar email personal legítimo."""
        nombre = self.get_random_name()

        subjects = [
            "Reunión de mañana",
            "Documentos que solicitaste",
            "Confirmación para el evento",
            "Consulta sobre el proyecto",
            "Seguimiento de nuestra conversación",
        ]

        bodies = [
            f"Hola,\n\nTe escribo para confirmar nuestra reunión de mañana a las 10:00 AM. ¿Te parece bien en la sala de conferencias?\n\nPor favor avísame si necesitas cambiar el horario.\n\nSaludos,\n{nombre}",

            f"Hola,\n\nTe adjunto los documentos que me pediste la semana pasada. Revísalos y avísame si necesitas algo más.\n\nCualquier duda, estoy disponible.\n\nSaludos cordiales,\n{nombre}",

            f"Buenos días,\n\nTe confirmo mi asistencia al evento del próximo viernes. ¿Necesitas que lleve algo en particular?\n\nQuedo atento.\n\nSaludos,\n{nombre}",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_receipt(self) -> Tuple[str, str]:
        """Generar recibo legítimo."""
        referencia = random.choice(self.numeros_referencia)
        monto = random.choice(self.montos)

        subjects = [
            f"Recibo de pago - {referencia}",
            f"Comprobante de transacción {referencia}",
            f"Tu recibo de ${monto} MXN",
        ]

        bodies = [
            f"Estimado cliente,\n\nSe ha procesado tu pago exitosamente.\n\nDetalles de la transacción:\n• Referencia: {referencia}\n• Monto: ${monto} MXN\n• Fecha: {datetime.now().strftime('%d/%m/%Y')}\n• Método de pago: Tarjeta terminada en {random.choice(self.numeros_cuenta)}\n\nEste es tu comprobante oficial.\n\nGracias por tu pago,\nDepartamento de Contabilidad",

            f"Hola,\n\nTu pago ha sido recibido correctamente.\n\nResumen:\n- Referencia: {referencia}\n- Importe: ${monto} MXN\n- Estado: Aprobado\n\nPuedes descargar tu factura desde tu cuenta.\n\nSaludos,\nEquipo de Pagos",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_meeting_reminder(self) -> Tuple[str, str]:
        """Generar recordatorio de reunión legítimo."""
        nombre = self.get_random_name()

        subjects = [
            "Recordatorio: Reunión de mañana a las 14:00",
            "Próxima reunión - Confirma tu asistencia",
            "Reunión programada para el jueves",
        ]

        bodies = [
            f"Hola equipo,\n\nLes recuerdo nuestra reunión programada para mañana:\n\nFecha: {(datetime.now() + timedelta(days=1)).strftime('%d de %B')}\nHora: 14:00 hrs\nLugar: Sala de conferencias B\nTema: Revisión de avances del proyecto\n\nPor favor confirmen su asistencia.\n\nSaludos,\n{nombre}",

            f"Estimados colegas,\n\nEsta es una confirmación de nuestra reunión:\n\n• Cuándo: Jueves 15:30 hrs\n• Dónde: Sala virtual (enlace en el calendario)\n• Duración: 1 hora\n• Agenda: Planificación del siguiente sprint\n\nNos vemos ahí.\n\nSaludos,\n{nombre}",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_project_update(self) -> Tuple[str, str]:
        """Generar actualización de proyecto legítima."""
        nombre = self.get_random_name()

        subjects = [
            "Actualización del proyecto - Fase 2 completada",
            "Avances del proyecto esta semana",
            "Estado del proyecto: En progreso",
        ]

        bodies = [
            f"Hola equipo,\n\nLes comparto el avance del proyecto:\n\n✓ Fase 1: Completada\n✓ Fase 2: Completada esta semana\n• Fase 3: En progreso (75%)\n• Fase 4: Pendiente\n\nProyección: Terminamos en 2 semanas si mantenemos el ritmo.\n\n¿Alguna pregunta o bloqueador?\n\nSaludos,\n{nombre}\nLíder de Proyecto",

            f"Buenas tardes,\n\nResumen semanal del proyecto:\n\nLogros:\n- Implementadas 5 nuevas funcionalidades\n- Resueltos 12 bugs\n- Documentación actualizada\n\nPendientes:\n- Revisión de código\n- Pruebas de integración\n\nNos vemos en la próxima reunión.\n\nSaludos,\n{nombre}",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_welcome_message(self) -> Tuple[str, str]:
        """Generar mensaje de bienvenida legítimo."""
        subjects = [
            "¡Bienvenido a nuestra plataforma!",
            "Gracias por registrarte",
            "Tu cuenta ha sido creada exitosamente",
        ]

        bodies = [
            f"¡Hola!\n\nBienvenido a nuestra plataforma. Estamos encantados de tenerte con nosotros.\n\nPara comenzar:\n1. Completa tu perfil\n2. Explora nuestras funcionalidades\n3. Únete a nuestra comunidad\n\nSi tienes alguna pregunta, nuestro equipo de soporte está disponible.\n\n¡Esperamos que disfrutes la experiencia!\n\nSaludos,\nEquipo de Bienvenida",

            f"Estimado usuario,\n\nGracias por unirte a nosotros. Tu registro se ha completado correctamente.\n\nTu nombre de usuario: {random.choice(self.nombres).lower()}{random.randint(100, 999)}\n\nPuedes iniciar sesión en cualquier momento desde nuestra página principal.\n\nBienvenido a bordo,\nEquipo de Registro",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_subscription_renewal(self) -> Tuple[str, str]:
        """Generar recordatorio de renovación legítimo."""
        subjects = [
            "Tu suscripción se renovará pronto",
            "Recordatorio: Renovación de suscripción",
            "Próxima renovación de tu plan",
        ]

        bodies = [
            f"Hola,\n\nTe informamos que tu suscripción se renovará automáticamente el {(datetime.now() + timedelta(days=30)).strftime('%d de %B')}.\n\nPlan actual: Premium\nCosto: $299 MXN/mes\nMétodo de pago: Tarjeta terminada en {random.choice(self.numeros_cuenta)}\n\nSi deseas modificar o cancelar tu suscripción, puedes hacerlo desde la configuración de tu cuenta en cualquier momento.\n\nGracias por tu preferencia,\nEquipo de Suscripciones",

            f"Estimado suscriptor,\n\nTu plan se renovará en 7 días. Aquí los detalles:\n\n• Plan: Profesional\n• Renovación: {(datetime.now() + timedelta(days=7)).strftime('%d/%m/%Y')}\n• Importe: $499 MXN\n\nNo necesitas hacer nada. La renovación es automática.\n\nPuedes gestionar tu suscripción desde tu cuenta.\n\nSaludos,\nAdministración",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_support_response(self) -> Tuple[str, str]:
        """Generar respuesta de soporte legítima."""
        ticket = random.choice(self.numeros_referencia)

        subjects = [
            f"Re: Tu solicitud de soporte #{ticket}",
            f"Respuesta a tu consulta - Ticket {ticket}",
            f"Caso resuelto: {ticket}",
        ]

        bodies = [
            f"Hola,\n\nGracias por contactarnos. Hemos revisado tu consulta (Ticket: {ticket}).\n\nRespuesta:\nHemos identificado el problema y lo hemos solucionado. Por favor intenta nuevamente y verifica que todo funcione correctamente.\n\nSi el problema persiste, responde a este correo y con gusto te ayudaremos.\n\nSaludos cordiales,\nEquipo de Soporte Técnico",

            f"Estimado usuario,\n\nTu ticket {ticket} ha sido atendido.\n\nSolución aplicada:\nSe actualizó tu configuración y se verificó el funcionamiento. Todo debería estar operando normalmente.\n\nPor favor confirma que el problema se ha resuelto.\n\n¿Podemos cerrar este caso?\n\nAtentamente,\nSoporte al Cliente",
        ]

        return random.choice(subjects), random.choice(bodies)

    def _generate_educational_content(self) -> Tuple[str, str]:
        """Generar contenido educativo legítimo."""
        subjects = [
            "Consejos de seguridad para proteger tu información",
            "Guía: Cómo identificar correos sospechosos",
            "Tips para mejorar tu productividad digital",
            "Buenas prácticas de seguridad en línea",
        ]

        bodies = [
            f"Hola,\n\nEn este boletín compartimos consejos importantes de seguridad:\n\n1. Usa contraseñas únicas y seguras\n2. Activa la autenticación de dos factores\n3. Mantén tu software actualizado\n4. Desconfía de enlaces y archivos sospechosos\n5. Verifica siempre la dirección del remitente\n\nLa seguridad es responsabilidad de todos.\n\nMás información en nuestro blog.\n\nSaludos,\nEquipo de Seguridad",

            f"Estimado usuario,\n\n¿Cómo identificar correos de phishing?\n\nSeñales de alerta:\n• Urgencia excesiva\n• Errores ortográficos\n• Remitentes desconocidos\n• Enlaces sospechosos\n• Solicitudes de información sensible\n\nSi recibes un correo sospechoso, repórtalo y elimínalo.\n\nTu seguridad es nuestra prioridad.\n\nSaludos,\nCentro de Educación Digital",
        ]

        return random.choice(subjects), random.choice(bodies)

    def generate_dataset(self,
                         total_emails: int = 1000,
                         phishing_ratio: float = 0.5) -> pd.DataFrame:
        """
        Generar dataset completo de correos sintéticos.

        Args:
            total_emails: Número total de correos a generar
            phishing_ratio: Proporción de correos de phishing (0.0 a 1.0)

        Returns:
            DataFrame con correos generados
        """
        self.logger.info(f"Generando {total_emails} correos sintéticos...")

        # Calcular cantidad de cada tipo
        num_phishing = int(total_emails * phishing_ratio)
        num_legitimate = total_emails - num_phishing

        emails = []

        # Generar correos de phishing
        self.logger.info(f"Generando {num_phishing} correos de phishing...")
        for i in range(num_phishing):
            if i % 100 == 0 and i > 0:
                self.logger.info(f"  Progreso phishing: {i}/{num_phishing}")
            emails.append(self.generate_phishing_email())

        # Generar correos legítimos
        self.logger.info(f"Generando {num_legitimate} correos legítimos...")
        for i in range(num_legitimate):
            if i % 100 == 0 and i > 0:
                self.logger.info(f"  Progreso legítimos: {i}/{num_legitimate}")
            emails.append(self.generate_legitimate_email())

        # Crear DataFrame
        df = pd.DataFrame(emails)

        # Mezclar el dataset
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)

        self.logger.info(f"✅ Dataset generado: {len(df)} correos")
        self.logger.info(f"   Phishing: {len(df[df['label'] == 'phishing'])}")
        self.logger.info(f"   Legítimos: {len(df[df['label'] == 'legitimate'])}")

        return df

    def save_to_csv(self, df: pd.DataFrame, output_file: str = None) -> str:
        """
        Guardar dataset en archivo CSV.

        Args:
            df: DataFrame a guardar
            output_file: Ruta del archivo de salida (opcional)

        Returns:
            Ruta del archivo guardado
        """
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"data/processed/synthetic_emails_{timestamp}.csv"

        # Asegurar que el directorio existe
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)

        # Guardar solo las columnas necesarias para el entrenamiento
        df_export = df[['text', 'label']].copy()
        df_export.to_csv(output_file, index=False, encoding='utf-8')

        self.logger.info(f"[Guardado] Dataset guardado en: {output_file}")
        self.logger.info(f"   Tamaño del archivo: {Path(output_file).stat().st_size / 1024:.2f} KB")

        return output_file

    def generate_statistics(self, df: pd.DataFrame) -> Dict[str, any]:
        """
        Generar estadísticas del dataset generado.

        Args:
            df: DataFrame a analizar

        Returns:
            Diccionario con estadísticas
        """
        stats = {
            'total_emails': len(df),
            'phishing_count': len(df[df['label'] == 'phishing']),
            'legitimate_count': len(df[df['label'] == 'legitimate']),
            'phishing_ratio': len(df[df['label'] == 'phishing']) / len(df),
            'avg_text_length': df['text'].str.len().mean(),
            'min_text_length': df['text'].str.len().min(),
            'max_text_length': df['text'].str.len().max(),
            'phishing_types': df[df['label'] == 'phishing']['type'].value_counts().to_dict(),
            'legitimate_types': df[df['label'] == 'legitimate']['type'].value_counts().to_dict()
        }

        return stats

    def print_statistics(self, stats: Dict):
        """Imprimir estadísticas del dataset."""
        print("\n" + "=" * 60)
        print("[Estadística] ESTADÍSTICAS DEL DATASET GENERADO")
        print("=" * 60)
        print(f"\n[Correos] Total de correos: {stats['total_emails']:,}")
        print(f"   • Phishing: {stats['phishing_count']:,} ({stats['phishing_ratio']:.1%})")
        print(f"   • Legítimos: {stats['legitimate_count']:,} ({1 - stats['phishing_ratio']:.1%})")

        print(f"\n[Texto] Longitud de texto:")
        print(f"   • Promedio: {stats['avg_text_length']:.0f} caracteres")
        print(f"   • Mínimo: {stats['min_text_length']}")
        print(f"   • Máximo: {stats['max_text_length']}")

        print(f"\n[Escenarios] Tipos de phishing:")
        for ptype, count in sorted(stats['phishing_types'].items(), key=lambda x: x[1], reverse=True):
            print(f"   • {ptype}: {count}")

        print(f"\n✅ Tipos de correos legítimos:")
        for ltype, count in sorted(stats['legitimate_types'].items(), key=lambda x: x[1], reverse=True):
            print(f"   • {ltype}: {count}")

        print("\n" + "=" * 60)


def main():
    """Función principal."""
    # Configurar argumentos
    parser = argparse.ArgumentParser(
        description='Generador de correos electrónicos sintéticos para entrenamiento ML'
    )
    parser.add_argument(
        '-n', '--num-emails',
        type=int,
        default=1000,
        help='Número total de correos a generar (default: 1000)'
    )
    parser.add_argument(
        '-r', '--phishing-ratio',
        type=float,
        default=0.5,
        help='Proporción de correos de phishing (0.0-1.0, default: 0.5)'
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        default=None,
        help='Archivo de salida (default: data/processed/synthetic_emails_TIMESTAMP.csv)'
    )
    parser.add_argument(
        '-s', '--seed',
        type=int,
        default=42,
        help='Semilla para reproducibilidad (default: 42)'
    )

    args = parser.parse_args()

    # Validar argumentos
    if args.num_emails < 10:
        print("❌ Error: El número mínimo de correos es 10")
        return 1

    if not 0.0 <= args.phishing_ratio <= 1.0:
        print("❌ Error: El ratio de phishing debe estar entre 0.0 y 1.0")
        return 1

    print("[Generador] Generador de Correos Sintéticos para Entrenamiento ML")
    print("=" * 60)
    print(f"\n⚙️  Configuración:")
    print(f"   • Total de correos: {args.num_emails:,}")
    print(f"   • Ratio de phishing: {args.phishing_ratio:.1%}")
    print(f"   • Correos de phishing: {int(args.num_emails * args.phishing_ratio):,}")
    print(f"   • Correos legítimos: {int(args.num_emails * (1 - args.phishing_ratio)):,}")
    print(f"   • Semilla: {args.seed}")

    try:
        # Crear generador
        generator = SyntheticEmailGenerator(seed=args.seed)

        # Generar dataset
        print(f"\n[Progreso] Generando correos...")
        df = generator.generate_dataset(
            total_emails=args.num_emails,
            phishing_ratio=args.phishing_ratio
        )

        # Guardar CSV
        output_file = generator.save_to_csv(df, args.output)

        # Generar y mostrar estadísticas
        stats = generator.generate_statistics(df)
        generator.print_statistics(stats)

        print(f"\n✅ ¡Generación completada exitosamente!")
        print(f"[Archivo] Archivo generado: {output_file}")
        print(f"\n[Nota] Próximo paso:")
        print(f"   python scripts/train_model.py")

        # Mostrar muestra de correos
        print(f"\n[Correos] Muestra de correos generados:")
        print("-" * 60)

        # Mostrar un phishing
        phishing_sample = df[df['label'] == 'phishing'].iloc[0]
        print(f"\n[Alerta] EJEMPLO DE PHISHING:")
        print(f"Asunto: {phishing_sample['subject']}")
        print(f"Texto: {phishing_sample['text'][:200]}...")

        # Mostrar un legítimo
        legit_sample = df[df['label'] == 'legitimate'].iloc[0]
        print(f"\n✅ EJEMPLO DE LEGÍTIMO:")
        print(f"Asunto: {legit_sample['subject']}")
        print(f"Texto: {legit_sample['text'][:200]}...")

        print("\n" + "=" * 60)

        return 0

    except KeyboardInterrupt:
        print("\n\n⚠️  Generación cancelada por el usuario")
        return 1

    except Exception as e:
        print(f"\n❌ Error durante la generación: {e}")
        logging.error(f"Error crítico: {e}")
        return 1


if __name__ == "__main__":
    exit(main())