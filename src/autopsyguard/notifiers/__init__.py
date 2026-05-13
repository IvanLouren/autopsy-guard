"""AutopsyGuard notification channels.

All three notifiers are importable directly from this package:

    from autopsyguard.notifiers import EmailNotifier, WhatsAppNotifier, TelegramNotifier
"""

from autopsyguard.notifiers.base import BaseNotifier
from autopsyguard.notifiers.email import EmailNotifier
from autopsyguard.notifiers.whatsapp import WhatsAppNotifier
from autopsyguard.notifiers.telegram import TelegramNotifier

__all__ = [
    "BaseNotifier",
    "EmailNotifier",
    "WhatsAppNotifier",
    "TelegramNotifier",
]
