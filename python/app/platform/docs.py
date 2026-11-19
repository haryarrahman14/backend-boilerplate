"""Swagger UI at /docs (development only; production serves neither /docs nor /openapi.json).

FastAPI's built-in page loads swagger-ui-dist@5 (a floating major) with no Subresource Integrity, so any
compromised or re-published 5.x would run on this origin. This page pins an exact version and its SRI hashes.
To upgrade: change the version, then recompute each hash with
`openssl dgst -sha384 -binary <file> | openssl base64 -A` on the files of that exact npm version.
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

SWAGGER_UI_VERSION = "5.34.1"
_CDN = f"https://cdn.jsdelivr.net/npm/swagger-ui-dist@{SWAGGER_UI_VERSION}"
_JS_SRI = "sha384-XFYN47VzPiDY6qPtxYKg0nqUeW/upo20xf1j2SUE7gT/i35FJB4cuS/71Iegzk8Z"
_CSS_SRI = "sha384-4c3vsE5f+trhFyHrFrLM1fFGUn531NIaC7dcqEWIJdoRQJ5CkJbSuSCwXLpaS1KF"

_PAGE = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{title}} - API docs</title>
  <link rel="stylesheet" href="{_CDN}/swagger-ui.css" integrity="{_CSS_SRI}" crossorigin="anonymous">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="{_CDN}/swagger-ui-bundle.js" integrity="{_JS_SRI}" crossorigin="anonymous"></script>
  <script>
    window.ui = SwaggerUIBundle({{ url: "{{openapi_url}}", dom_id: "#swagger-ui", deepLinking: true }});
  </script>
</body>
</html>
"""


def install_docs(app: FastAPI, openapi_url: str = "/openapi.json") -> None:
    page = _PAGE.replace("{title}", app.title).replace("{openapi_url}", openapi_url)

    @app.get("/docs", include_in_schema=False)
    async def docs() -> HTMLResponse:
        return HTMLResponse(page)
