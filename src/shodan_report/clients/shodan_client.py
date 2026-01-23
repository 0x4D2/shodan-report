from typing import Optional, Any


class ShodanClient:
    """Small wrapper around the official `shodan` package.

    The optional third-party package is imported lazily when an instance is
    created so unit tests can import this module without having `shodan`
    installed. You can also inject a pre-configured client (useful for tests).
    """

    def __init__(self, api_key: Optional[str] = None, client: Optional[Any] = None):
        """Create a `ShodanClient`.

        Args:
            api_key: Shodan API key. Required if `client` is not provided.
            client: Optional pre-built client instance (for testing/mocking).
        """
        self._shodan_module = None

        if client is not None:
            self.client = client
            return

        try:
            import shodan as _shodan  # type: ignore
        except ImportError as e:
            raise ImportError(
                "Optionales Paket 'shodan' nicht installiert. Bitte 'pip install shodan' ausführen."
            ) from e

        if not api_key:
            raise ValueError("API-Key fehlt!")

        self._shodan_module = _shodan
        self.client = _shodan.Shodan(api_key)

    def get_host(self, ip: str, retries: int = 1) -> dict:
        """Retrieve host information from Shodan.

        Args:
            ip: IP address to query.
            retries: Number of attempts on transient errors.

        Raises:
            RuntimeError: On errors from the Shodan client.
        """
        last_exc: Optional[Exception] = None
        for attempt in range(retries):
            try:
                return self.client.host(ip)
            except Exception as e:
                last_exc = e
        # If we reach here, all retries failed
        raise RuntimeError(f"Fehler beim Abfragen von Shodan für {ip}: {last_exc}") from last_exc
