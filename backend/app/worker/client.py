import httpx


class ApiUnavailable(Exception):
    """The API could not be reached or had a problem of its own; worth retrying."""


class ApiClient:
    """The worker's only way out: POSTs to the internal API. `http` is an httpx.Client with
    the base URL and the Authorization header set (tests pass a TestClient instead)."""

    def __init__(self, http: httpx.Client) -> None:
        self.http = http

    def post(
        self, path: str, body: dict, *, claim_token: str | None = None, timeout: float = 15.0
    ) -> httpx.Response:
        headers = {"X-Claim-Token": claim_token} if claim_token else {}
        try:
            response = self.http.post(path, json=body, headers=headers, timeout=timeout)
        except httpx.HTTPError as exc:
            raise ApiUnavailable(f"{path}: {exc.__class__.__name__}: {exc}") from exc
        if response.status_code >= 500 or response.status_code in (401, 429):
            raise ApiUnavailable(f"{path}: HTTP {response.status_code}")
        return response
