package web

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"

	zerovault "zerovault"
)

// pages lists every content template that gets combined with layout.html.
var pages = []string{"unlock", "dashboard", "add", "edit", "view", "totp", "generate", "scanner", "file", "health", "settings", "about", "audit"}

// templateSet holds one *template.Template per page, each containing both
// layout.html's "layout" definition and that page's "content" definition.
type templateSet map[string]*template.Template

func loadTemplates() (templateSet, error) {
	set := make(templateSet, len(pages))
	for _, page := range pages {
		tmpl, err := template.ParseFS(zerovault.TemplateFiles,
			"web/templates/layout.html",
			"web/templates/partials.html",
			fmt.Sprintf("web/templates/%s.html", page),
		)
		if err != nil {
			return nil, fmt.Errorf("web: failed to parse template %q: %w", page, err)
		}
		set[page] = tmpl
	}
	return set, nil
}

// render executes the named page's layout template. html/template
// auto-escapes all dynamic content, so no manual XSS sanitization is
// needed for anything passed in data.
//
// Executed into a buffer first, not straight to w: ExecuteTemplate can
// fail partway through (a broken client connection, a template data
// error) after already having written some bytes — writing to w directly
// would leave a half-rendered page on the wire and then try to call
// http.Error on a response that already started, which is a no-op at
// best and confusing at worst. Buffering means a failed render never
// reaches the browser as broken HTML with a 200 status.
func (s *Server) render(w http.ResponseWriter, page string, data any) {
	tmpl, ok := s.templates[page]
	if !ok {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		http.Error(w, "failed to render page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}
