package web

import (
	"io/fs"
	"net/http"

	zerovault "zerovault"
)

// staticHandler serves the embedded web/static assets at /static/, stripped
// down to an fs.FS rooted at "web/static" so /static/style.css resolves to
// the embedded web/static/style.css.
func staticHandler() (http.Handler, error) {
	sub, err := fs.Sub(zerovault.StaticFiles, "web/static")
	if err != nil {
		return nil, err
	}
	return http.StripPrefix("/static/", http.FileServerFS(sub)), nil
}
