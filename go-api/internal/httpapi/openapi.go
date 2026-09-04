package httpapi

import (
	_ "embed"
	"net/http"
)

// The OpenAPI document is hand-authored rather than generated, so it says what
// the service actually accepts instead of what a struct tag implies. The cost
// of hand-authoring is drift, so a test cross-checks its paths against the
// route table: the document and the router cannot disagree without failing.
//
//go:embed openapi.json
var openAPIJSON []byte

func (s *Server) openAPIDocument(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(openAPIJSON); err != nil {
		return
	}
}

// The renderers load their assets from a public CDN, which is the same posture
// FastAPI's built-in /docs has in the Python service. A deployment without
// egress to the CDN gets an unstyled page; /openapi.json still serves the
// document, and ENABLE_DOCS=false removes all three routes.
const (
	swaggerCSS    = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css"
	swaggerBundle = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"
	redocBundle   = "https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js"
)

func (s *Server) swaggerUI(w http.ResponseWriter, _ *http.Request) {
	writeHTML(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>control-translation — API</title>
<link rel="stylesheet" href="`+swaggerCSS+`">
</head>
<body>
<div id="swagger-ui"></div>
<script src="`+swaggerBundle+`" crossorigin></script>
<script>
  window.ui = SwaggerUIBundle({
    url: "/openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    // A decline is a 200 with a typed body, so the schema matters more than
    // the status code when reading a response here.
    defaultModelsExpandDepth: 0,
  });
</script>
</body>
</html>`)
}

func (s *Server) redoc(w http.ResponseWriter, _ *http.Request) {
	writeHTML(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>control-translation — API</title>
<style>body { margin: 0; }</style>
</head>
<body>
<redoc spec-url="/openapi.json"></redoc>
<script src="`+redocBundle+`"></script>
</body>
</html>`)
}

func writeHTML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write([]byte(body)); err != nil {
		return
	}
}
