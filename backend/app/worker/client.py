import httpx


class ApiUnavailable(Exception):
    """The API could not be reached or had a problem of its own; worth retrying."""


class ApiRefused(Exception):
    """The API answered, but not with what was asked for; retrying won't help."""


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

    def download(
        self, path: str, body: dict, *, claim_token: str, max_bytes: int, timeout: float = 120.0
    ) -> bytes:
        """POSTs and returns the response body, refusing to read more than max_bytes."""
        headers = {"X-Claim-Token": claim_token}
        try:
            with self.http.stream(
                "POST", path, json=body, headers=headers, timeout=timeout
            ) as response:
                if response.status_code >= 500 or response.status_code in (401, 429):
                    raise ApiUnavailable(f"{path}: HTTP {response.status_code}")
                if response.status_code != 200:
                    raise ApiRefused(f"{path}: HTTP {response.status_code}")
                chunks: list[bytes] = []
                received = 0
                for chunk in response.iter_bytes():
                    received += len(chunk)
                    if received > max_bytes:
                        raise ApiRefused(f"{path}: more than {max_bytes} bytes")
                    chunks.append(chunk)
                return b"".join(chunks)
        except httpx.HTTPError as exc:
            raise ApiUnavailable(f"{path}: {exc.__class__.__name__}: {exc}") from exc
