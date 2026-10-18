"""Base abstraction for upstream Identity Providers."""

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseIdPProvider(ABC):
    """Abstract Identity Provider client."""

    @abstractmethod
    def get_login_url(self, state: str, redirect_uri: str) -> str:
        """Returns the URL where the user is redirected to log in."""
        pass

    @abstractmethod
    async def exchange_code_for_user(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        """Exchanges upstream authorization code for authenticated user claims."""
        pass
