package main

import (
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"ktkr.us/pkg/airlift/config"
)

//go:embed templates
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// templates holds one parsed template group per content file, each cloned from
// the shared layouts. A group is keyed by the content file's base name without
// extension, e.g. "config", "history", "login".
var templates = map[string]*template.Template{}

// renderRoot is the top-level object passed to every template execution. The
// templates reference the payload as "$.Data"; see appCtx for the usual
// payload, though some pages (e.g. login) pass a bare value instead.
type renderRoot struct {
	Data interface{}
}

// appCtx is the common template payload. It exposes global state (Version,
// Config) plus a page-specific Data field, matching the pre-rewrite templates.
type appCtx struct {
	Data interface{}
}

func (appCtx) Version() string        { return version }
func (appCtx) Config() *config.Config { return config.Get() }

// page wraps page-specific data in the standard context.
func page(data interface{}) renderRoot { return renderRoot{&appCtx{Data: data}} }

// raw wraps a bare value (used by templates that test "$.Data" directly).
func raw(data interface{}) renderRoot { return renderRoot{data} }

func parseTemplates() {
	layouts := template.Must(template.New("layouts").ParseFS(templateFS, "templates/layout/*.tmpl"))

	entries, err := templateFS.ReadDir("templates/content")
	if err != nil {
		log.Fatalln("templates:", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tmpl") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".tmpl")
		t := template.Must(layouts.Clone())
		t = template.Must(t.ParseFS(templateFS, "templates/content/"+e.Name()))
		templates[name] = t
	}
}

// render writes the named template ("group/name", e.g. "config/layout-full")
// to w with the given root payload.
func render(w http.ResponseWriter, code int, path string, root renderRoot) {
	group, name, ok := strings.Cut(path, "/")
	if !ok {
		log.Printf("render: bad template path %q", path)
		http.Error(w, "internal error", 500)
		return
	}
	t := templates[group]
	if t == nil {
		log.Printf("render: no such template group %q", group)
		http.Error(w, "internal error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	if err := t.ExecuteTemplate(w, name, root); err != nil {
		log.Printf("render %s: %v", path, err)
	}
}

// staticHandler serves the embedded static assets under /-/static/.
func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalln("static:", err)
	}
	return http.StripPrefix("/-/static/", http.FileServer(http.FS(sub)))
}

// threeMonths is the cache lifetime advertised for uploaded files.
const threeMonths = 90 * 24 * time.Hour
