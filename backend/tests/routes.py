"""The app's real API routes, for tests that inspect guards and scopes.

FastAPI (0.141) wraps every included router in a lazy `_IncludedRouter`, so `app.routes`
contains no `APIRoute` at all: a test that loops over it and skips non-APIRoutes passes
while checking nothing. This flattens the wrappers into objects exposing the same
`.path`, `.methods` and `.dependant` a route has, as actually served (prefix and
include-level dependencies applied), and cross-checks the count against the public
OpenAPI schema so it can never silently return too few again.
"""

from fastapi import FastAPI
from fastapi.routing import APIRoute


def iter_api_routes(app: FastAPI) -> list:
    found: list = []

    def visit(included) -> None:
        for item in included.effective_candidates():
            if type(item).__name__ == "_IncludedRouter":
                visit(item)
            elif isinstance(item.original_route, APIRoute):
                found.append(item)

    for route in app.routes:
        if type(route).__name__ == "_IncludedRouter":
            visit(route)
        elif isinstance(route, APIRoute):
            found.append(route)

    served = {
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        for method in operations
    }
    flattened = {(method, route.path) for route in found for method in route.methods}
    missing = served - flattened
    assert not missing, f"route enumeration is missing served operations: {sorted(missing)}"
    assert len(flattened) > 30, "route enumeration returned suspiciously few routes"
    return found
