import json
from typing import Any, Dict, Tuple, Optional


class NvdClient:
	"""Minimal NVD client used by tests.

	The real project likely implements HTTP calls; tests only rely on
	`_default_headers()` and `fetch_cve_json()` (they monkeypatch
	`fetch_cve`), so this minimal implementation is sufficient for tests.
	"""

	def __init__(self, api_key: Optional[str] = None) -> None:
		self.api_key = api_key

	def _default_headers(self) -> Dict[str, str]:
		headers: Dict[str, str] = {}
		if self.api_key:
			headers['apiKey'] = self.api_key
		return headers

	def fetch_cve(self, cve_id: str) -> Tuple[int, Dict[str, Any], str]:
		"""Placeholder for actual fetch implementation.

		Returns a tuple of (status_code, headers, body). The tests monkeypatch
		this method, so raising NotImplementedError is acceptable for now.
		"""
		raise NotImplementedError("HTTP fetch not implemented in test stub")

	def fetch_cve_json(self, cve_id: str) -> Dict[str, Any]:
		status, headers, body = self.fetch_cve(cve_id)
		try:
			return json.loads(body)
		except Exception as exc:  # pragma: no cover - defensive
			raise ValueError(f"failed to parse CVE JSON: {exc}")


__all__ = ["NvdClient"]
