// Package zerovault embeds the web dashboard's templates and static assets
// at the module root (the only place a //go:embed directive can reach the
// top-level web/ directory without a disallowed ".." pattern), so the
// compiled binary is fully self-contained with no external files needed
// at runtime.
package zerovault

import "embed"

//go:embed web/static
var StaticFiles embed.FS

//go:embed web/templates
var TemplateFiles embed.FS
