from __future__ import annotations

import logging

from authub.email.base import EmailMessage, EmailSender

logger = logging.getLogger(__name__)


class ConsoleEmailSender(EmailSender):
    """``EmailSender`` that logs the recipient and subject instead of delivering mail."""

    async def send(self, message: EmailMessage) -> None:
        logger.info("email (not sent): to=%s subject=%s", message.to, message.subject)
