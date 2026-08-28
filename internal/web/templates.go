package web

import (
	"fmt"
	"html/template"
	"net/http"

	zerovault "zerovault"
)

// pages lists every content template that gets combined with layout.html.
var pages = []string{"unlock", "dashboard", "add", "view", "totp", "generate", "scanner", "file", "health"}

// templateSet holds one *template.Template per page, each containing both
// layout.html's "layout" definition and that page's "content" definition.
type templateSet map[string]*template.Template

func loadTemplates() (templateSet, error) {
	set := make(templateSet, len(pages))
	for _, page := range pages {
		tmpl, err := template.ParseFS(zerovault.TemplateFiles,
			"web/templates/layout.html",
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
func (s *Server) render(w http.ResponseWriter, page string, data any) {
	tmpl, ok := s.templates[page]
	if !ok {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "failed to render page", http.StatusInternalServerError)
	}
}
