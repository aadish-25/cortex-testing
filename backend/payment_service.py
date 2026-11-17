"""
Enterprise Billing & Payment Processing Service.
Handles Stripe webhook signature validation, idempotency checks,
refund processing, and PDF invoice receipt generation.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone
import os
import logging
import stripe

logger = logging.getLogger(__name__)

STRIPE_API_KEY = os.getenv("STRIPE_API_KEY", "sk_test_mock_stripe_key")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_mock_stripe_webhook_secret")
stripe.api_key = STRIPE_API_KEY


class PaymentError(Exception):
    """Base exception for payment domain errors."""
    pass


class SignatureVerificationError(PaymentError):
    """Raised when Stripe webhook signature is invalid or forged."""
    pass


class IdempotencyViolationError(PaymentError):
    """Raised when duplicate webhook event is processed."""
    pass


class PaymentService:
    def __init__(self, event_store=None, invoice_repository=None):
        self.event_store = event_store
        self.invoice_repo = invoice_repository

    def verify_and_construct_webhook_event(
        self,
        payload_bytes: bytes,
        sig_header: str,
        tolerance: int = 300
    ) -> stripe.Event:
        """
        Verify incoming webhook signature using Stripe SDK to prevent replay and timing attacks.
        Checks event timestamp against tolerance (default 300s).
        """
        if not sig_header:
            raise SignatureVerificationError("Missing Stripe-Signature header")

        try:
            event = stripe.Webhook.construct_event(
                payload=payload_bytes,
                sig_header=sig_header,
                secret=STRIPE_WEBHOOK_SECRET,
                tolerance=tolerance
            )
        except stripe.error.SignatureVerificationError as e:
            logger.error("Webhook signature verification failed: %s", str(e))
            raise SignatureVerificationError(f"Invalid webhook signature: {str(e)}")
        except ValueError as e:
            logger.error("Invalid webhook payload format: %s", str(e))
            raise PaymentError(f"Invalid payload format: {str(e)}")

        # Idempotency safeguard: check whether this event ID has already been recorded
        if self.event_store and self.event_store.has_processed(event.id):
            logger.warning("Duplicate webhook event received: %s", event.id)
            raise IdempotencyViolationError(f"Duplicate event already processed: {event.id}")

        return event

    def process_webhook_event(self, event: stripe.Event) -> Dict[str, Any]:
        """Dispatch verified Stripe event to appropriate handler."""
        event_type = event.get("type")
        event_data = event.get("data", {}).get("object", {})

        logger.info("Processing Stripe event %s [ID: %s]", event_type, event.id)

        if event_type == "payment_intent.succeeded":
            return self._handle_payment_intent_succeeded(event_data)
        elif event_type == "charge.refunded":
            return self._handle_charge_refunded(event_data)
        elif event_type == "invoice.payment_succeeded":
            return self._handle_invoice_payment_succeeded(event_data)
        else:
            logger.debug("Unhandled event type %s ignored", event_type)
            return {"status": "ignored", "event_id": event.id}

    def _handle_payment_intent_succeeded(self, payment_intent: Dict[str, Any]) -> Dict[str, Any]:
        customer_id = payment_intent.get("customer")
        amount = payment_intent.get("amount")
        currency = payment_intent.get("currency")
        logger.info(
            "PaymentIntent succeeded: %s for customer %s (%s %s)",
            payment_intent.get("id"), customer_id, amount, currency
        )
        return {"status": "success", "action": "order_confirmed", "amount": amount}

    def _handle_charge_refunded(self, charge: Dict[str, Any]) -> Dict[str, Any]:
        charge_id = charge.get("id")
        amount_refunded = charge.get("amount_refunded")
        logger.info("Charge %s refunded amount: %d", charge_id, amount_refunded)
        return {"status": "success", "action": "refund_recorded", "amount_refunded": amount_refunded}

    def _handle_invoice_payment_succeeded(self, invoice: Dict[str, Any]) -> Dict[str, Any]:
        invoice_id = invoice.get("id")
        customer_email = invoice.get("customer_email")
        receipt_url = self.generate_invoice_receipt(invoice_id, customer_email, invoice.get("amount_paid"))
        return {"status": "success", "action": "receipt_generated", "receipt_url": receipt_url}

    def process_refund(
        self,
        charge_id: str,
        amount_cents: Optional[int] = None,
        reason: str = "requested_by_customer"
    ) -> stripe.Refund:
        """
        Execute refund for an existing charge via Stripe API.
        Supports partial refunds when amount_cents is specified.
        """
        try:
            params: Dict[str, Any] = {
                "charge": charge_id,
                "reason": reason,
                "metadata": {
                    "initiated_at": datetime.now(timezone.utc).isoformat(),
                    "service": "billing_platform"
                }
            }
            if amount_cents is not None:
                params["amount"] = amount_cents

            refund = stripe.Refund.create(**params)
            logger.info("Refund created successfully: %s for charge %s", refund.id, charge_id)
            return refund
        except stripe.error.StripeError as exc:
            logger.error("Failed to process refund for charge %s: %s", charge_id, exc)
            raise PaymentError(f"Stripe refund failed: {exc.user_message or str(exc)}")

    def generate_invoice_receipt(
        self,
        invoice_id: str,
        customer_email: str,
        amount_paid: int,
        currency: str = "usd"
    ) -> str:
        """
        Generate invoice receipt metadata and return downloadable receipt URL.
        """
        receipt_data = {
            "receipt_number": f"REC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{invoice_id[-6:]}",
            "invoice_id": invoice_id,
            "recipient": customer_email,
            "amount": f"{amount_paid / 100:.2f} {currency.upper()}",
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }
        if self.invoice_repo:
            self.invoice_repo.save_receipt(receipt_data)

        logger.info("Generated invoice receipt %s for invoice %s", receipt_data["receipt_number"], invoice_id)
        return f"https://billing.cortex.internal/receipts/{receipt_data['receipt_number']}.pdf"
