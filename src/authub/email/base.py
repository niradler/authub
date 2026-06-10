from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel, EmailStr


class EmailMessage(BaseModel):
    """Payload for a single outbound email."""

    to: EmailStr
    subject: str
    text: str
    html: str | None = None


class EmailSender(ABC):
    """Abstract interface for sending email. Implement to integrate a real mail provider."""

    @abstractmethod
    async def send(self, message: EmailMessage) -> None:
        """Deliver the message. Raise on failure."""
        ...
